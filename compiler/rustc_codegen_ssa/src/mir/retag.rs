//! Experimental support for emitting retags as function calls.
//!
//! Both Stacked and Tree Borrows rely retag operations to create
//! and update the permissions associated with pointers. This module provides support
//! for emitting retags as function calls, making it possible to find aliasing violations
//! in lower-level representations of Rust programs. The underlying functions do not
//! actually exist; they are just a vehicle for lowering type and aliasing information.
//!
//! There are two kinds of retag intrinsics. The first variant, `__rust_retag_reg`,
//! is used to retag a pointer that has already been loaded into a register. Its first
//! argument is the pointer being retagged, and it returns an alias with the same address,
//! but different provenance. The second variant, `__rust_retag_mem` is used to retag a
//! pointer stored within a place. It receives a pointer to the place. If we used the `reg`
//! variant instead, then we would need to load the pointer from the place and store the
//! retagged result back to reflect that its provenance had changed. If the place has LLVM's
//! `readonly` attribute or equivalent, then this additional store is undefined behavior.
//! The `mem` variant communicates this level of indirection without having to insert an
//! explicit store. The remaining arguments are the same for each variant.
//!
//! * Size (`i64`) - The size of the permission created by the retag.
//! * Permissions (`i8`) - A set of flags encoding the type of permission (see [`RetagFlags`])
//! * Interior Mutable Ranges (`ptr`) - A pointer to a global array of the ranges covered by `UnsafeCell`.
//! * Pinned Ranges (`ptr`) - A pointer to a global array of the ranges covered by `UnsafePinned`.
//!
//! We attempt to retag every argument and return value of a function, and every rvalue
//! of an assignment. The first step to retagging is to generate a [`RetagPlan`], which
//! describes which pointers within the place or operand can be retagged. We traverse
//! the [`RetagPlan`] to codegen each call, as needed.

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::interpret::Allocation;
use rustc_middle::mir::{Rvalue, WithRetag};
use rustc_middle::ty;
use rustc_middle::ty::Mutability;
use rustc_middle::ty::layout::HasTypingEnv;

use super::{BuilderMethods, FunctionCx};
use crate::mir::operand::{OperandRef, OperandRefBuilder, OperandValue};
use crate::mir::place::PlaceRef;
use crate::mir::{Ty, TyAndLayout};
use crate::traits::{BaseTypeCodegenMethods, CodegenMethods};
use crate::{FxIndexMap, RetagFlags, RetagInfo};

pub(crate) fn rvalue_needs_retag(rvalue: &Rvalue<'_>) -> bool {
    // `Ref` has its own internal retagging
    !matches!(rvalue, Rvalue::Ref(..)) && !matches!(rvalue, Rvalue::Use(.., WithRetag::No))
}

/// A description of the pointers within a type that are affected by a retag.
#[derive(Debug)]
enum RetagPlan<V> {
    /// Indicates that a pointer should be retagged.
    EmitRetag(RetagInfo<V>),

    /// Indicates that one or more fields or variants of this type
    /// contain pointers that need to be retagged.
    Recurse {
        field_plans: FxIndexMap<FieldIdx, RetagPlan<V>>,
        variant_plans: FxIndexMap<VariantIdx, RetagPlan<V>>,
    },
}

impl<V> RetagPlan<V> {
    /// A helper function to move a [`RetagPlan`] into a particular field.
    fn for_field(self, ix: FieldIdx) -> Self {
        let mut field_plans = FxIndexMap::default();
        field_plans.insert(ix, self);
        RetagPlan::Recurse { field_plans, variant_plans: FxIndexMap::default() }
    }
}

impl<'a, 'tcx, V> RetagPlan<V> {
    /// Attempts to create a [`RetagPlan`] for a place or operand with the given layout.
    fn build<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        // If the value being retagged is smaller than a pointer, then it can't contain any
        // pointers we need to retag, so we can stop recursion early. This optimization is crucial
        // for ZSTs, because they can contain way more fields than we can ever visit.
        if layout.is_sized() && layout.size < bx.tcx().data_layout.pointer_size() {
            return None;
        }
        // SIMD vectors may only contain raw pointers, integers, and floating point values,
        // which do not need to be retagged.
        if matches!(layout.backend_repr, BackendRepr::SimdVector { .. }) {
            return None;
        }

        // Check the type of this value to see what to do with it (retag, or recurse).
        match layout.ty.kind() {
            &ty::Ref(_, pointee, mt) => {
                let pointee_layout = bx.layout_of(pointee);
                Self::emit_retag(bx, pointee_layout, Some(mt), is_fn_entry)
            }
            &ty::RawPtr(_, _) => None,
            // `Box` needs special handling, since the innermost pointer is what gets retagged, but
            // though the outermost `Box` is what determines the permission that gets created.
            ty::Adt(adt, _) if adt.is_box() => Self::visit_box(bx, layout, is_fn_entry),
            // Skip traversing for everything inside of `MaybeDangling`
            ty::Adt(adt, _) if adt.is_maybe_dangling() => None,
            _ => Self::walk_value(bx, layout, is_fn_entry),
        }
    }

    /// Recurses through the fields and variants of a value in memory order to create a [`RetagPlan`].
    fn walk_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        let mut field_plans = FxIndexMap::default();
        let mut variant_plans = FxIndexMap::default();

        match &layout.fields {
            FieldsShape::Union(_) | FieldsShape::Primitive => {}
            _ => {
                for ix in layout.fields.index_by_increasing_offset() {
                    let field_layout = layout.field(bx, ix);
                    if let Some(plan) = Self::build(bx, field_layout, is_fn_entry) {
                        field_plans.insert(FieldIdx::from_usize(ix), plan);
                    }
                }
            }
        }

        match &layout.variants {
            Variants::Single { .. } | Variants::Empty => {}
            Variants::Multiple { variants, .. } => {
                for ix in variants.indices() {
                    let variant_layout = layout.for_variant(bx, ix);
                    if let Some(plan) = Self::build(bx, variant_layout, is_fn_entry) {
                        variant_plans.insert(ix, plan);
                    }
                }
            }
        }

        (!field_plans.is_empty() || !variant_plans.is_empty())
            .then(|| RetagPlan::Recurse { field_plans, variant_plans })
    }

    /// Emits a retag for a `Box`.
    fn visit_box<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        assert!(layout.ty.is_box());
        assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");
        let mut field_plans = FxIndexMap::default();

        // Only retag the inner pointer of a `Box` if it came from the global allocator.
        if layout.ty.is_box_global(bx.tcx()) {
            let boxed_ty = layout.ty.expect_boxed_ty();
            let boxed_layout = bx.layout_of(boxed_ty);
            if let Some(mut plan) = Self::emit_retag(bx, boxed_layout, None, is_fn_entry) {
                // `Unique<T>`
                let unique = layout.field(bx, 0);
                assert_eq!(unique.fields.count(), 2);
                plan = plan.for_field(FieldIdx::ZERO);

                // `NonNull<T>`
                let nonnull = unique.field(bx, 0);
                assert_eq!(nonnull.fields.count(), 1);
                plan = plan.for_field(FieldIdx::ZERO);

                // ``*mut T is !null``
                let pattern = nonnull.field(bx, 0);
                let ty::Pat(base, _) = pattern.ty.kind() else {
                    unreachable!("`NonNull` should contain a pattern type")
                };
                assert_eq!(base.builtin_deref(true), Some(boxed_ty));

                field_plans.insert(FieldIdx::ZERO, plan);
            }
        }

        // We always try to retag the second field (the allocator)
        let field_layout = layout.field(bx, 1);
        if let Some(plan) = Self::build(bx, field_layout, is_fn_entry) {
            field_plans.insert(FieldIdx::ONE, plan);
        }

        (!field_plans.is_empty())
            .then(|| RetagPlan::Recurse { field_plans, variant_plans: FxIndexMap::default() })
    }

    /// Attempts to retag a pointer to a type with the given layout.
    /// Returns `None` for mutable pointers to types that are entirely
    /// covered by `UnsafePinned`, for which retags are a noop.
    fn emit_retag<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        pointee_layout: TyAndLayout<'tcx>,
        ptr_kind: Option<Mutability>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        let opts = bx.tcx().sess.opts.unstable_opts.codegen_emit_retag.unwrap_or_default();

        let pointee_ty = pointee_layout.ty;
        let pin_ranges = UnsafePinnedRanges::collect(bx, pointee_layout, opts.no_precise_pin);

        let is_mutable = matches!(ptr_kind, Some(Mutability::Mut) | None);
        let is_unpin = UnsafePinnedRanges::excludes(bx, pointee_ty);
        let is_freeze = UnsafeCellRanges::excludes(bx, pointee_ty);
        let is_box = ptr_kind.is_none();

        // `&mut !Unpin` is not protected
        let is_protected = is_fn_entry && (!is_mutable || is_unpin);

        if is_mutable {
            // Everything is `UnsafePinned` if we only have a single
            // range starting at 0 and covering the size of the type.
            let all_pinned = matches!(
                pin_ranges.as_slice(),
                [[Size::ZERO, size]] if *size == pointee_layout.size,
            );

            // Otherwise, even if we can't find any `UnsafePinned`,
            // the type is still might be `!Unpin` or `!UnsafeUnpin`,
            // so we should include the entire range.
            let implicitly_pinned = pin_ranges.is_empty() && !is_unpin;

            if all_pinned || implicitly_pinned {
                return None;
            }
        }

        let im_ranges = UnsafeCellRanges::collect(bx, pointee_layout, opts.no_precise_im);
        let all_im = matches!(
            im_ranges.as_slice(),
            [[Size::ZERO, size]] if *size == pointee_layout.size,
        );

        // If the entire type is covered by `UnsafeCell`, then we can
        // defer to checking if the type is Freeze via RetagFlags, instead
        // of allocating a global array, which is expensive at runtime.
        let im_layout =
            if all_im { bx.const_null(bx.type_ptr()) } else { Self::alloc_ranges(bx, im_ranges) };

        let mut flags = RetagFlags::empty();
        flags.set(RetagFlags::IS_PROTECTED, is_protected);
        flags.set(RetagFlags::IS_MUTABLE, is_mutable);
        flags.set(RetagFlags::IS_BOX, is_box);

        // We need to track `Freeze` separately from `UnsafeCellRanges` so that we can
        // handle ZSTs, which still need to be treated as interior mutable (e.g. `UnsafeCell<()>`).
        flags.set(RetagFlags::IS_FREEZE, is_freeze);

        Some(RetagPlan::EmitRetag(RetagInfo {
            size: pointee_layout.size,
            im_layout,
            pin_layout: Self::alloc_ranges(bx, pin_ranges),
            flags,
        }))
    }

    /// Creates a pointer to a global static allocation containing adjacent pairs of `usize` bytes,
    /// which indicate the offset and width of a range within the layout of a type. Returns a null
    /// pointer if the list of ranges is empty.
    fn alloc_ranges<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        ranges: Vec<[Size; 2]>,
    ) -> Bx::Value {
        let tcx = bx.tcx();
        let data_layout = &tcx.data_layout;

        if ranges.is_empty() {
            return bx.const_null(bx.type_ptr());
        }

        let bytes: Vec<u8> =
            ranges.iter().flatten().flat_map(|u| u.bytes_usize().to_ne_bytes()).collect();

        let intptr_ty = data_layout.ptr_sized_integer();
        let align = intptr_ty.align(data_layout).abi;

        let alloc = Allocation::from_bytes(&bytes, align, Mutability::Not, ());
        let const_alloc = tcx.mk_const_alloc(alloc);

        // Different IDs are produced, but identical range lists
        // will resolve to the same allocation.
        let alloc_id = tcx.reserve_and_set_memory_alloc(const_alloc);
        let global_alloc = tcx.global_alloc(alloc_id);
        let global_mem = global_alloc.unwrap_memory();

        bx.cx().static_addr_of(global_mem, None)
    }
}

/// A visitor trait for collecting the ranges within a layout that satisfy a given predicate.
trait PerByteTracking<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> {
    /// Indicates that we can exclude the range of bytes that contains this type.
    /// This tells us that [`PerByteTracking::contains`] is false for every
    /// field or variant without having to recurse any further into the layout of the type.
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool;

    /// Indicates that we should include the range containing this type.
    fn contains(bx: &mut Bx, ty: Ty<'tcx>) -> bool;

    /// Traverses through the layout of a type to find each range satisfying
    /// the predicate.
    ///
    /// If `imprecise` is true, then the entire size of the type will be included
    /// even if only one of its fields satisfies the predicate.
    fn visit_layout(
        bx: &mut Bx,
        collector: &mut RangeCollector,
        layout: TyAndLayout<'tcx>,
        base_offset: Size,
        imprecise: bool,
    ) {
        if Self::excludes(bx, layout.ty) {
            return;
        }

        if imprecise {
            return collector.extend(layout.size);
        }

        let union_or_primitive =
            matches!(layout.fields, FieldsShape::Union(..) | FieldsShape::Primitive);
        let has_multiple_variants = matches!(layout.variants, Variants::Multiple { .. });

        if Self::contains(bx, layout.ty) || union_or_primitive || has_multiple_variants {
            collector.extend(layout.size);
        } else {
            // We know at this point that we have an array or an arbitrary layout.
            for ix in layout.fields.index_by_increasing_offset() {
                // We need to find the offset for this field relative
                // to the entire type, not just the current aggregate
                // that we are visiting here.
                let field_offset = layout.fields.offset(ix);
                let layout_offset = field_offset + base_offset;
                collector.advance(layout_offset);

                let field = layout.field(bx, ix);
                Self::visit_layout(bx, collector, field, layout_offset, imprecise);
            }
        }
    }
    /// Collects the ranges within a type that satisfy the given predicate. A range is a
    /// pair of [`Size`], representing the offset and width, respectively.
    fn collect(bx: &mut Bx, layout: TyAndLayout<'tcx>, imprecise: bool) -> Vec<[Size; 2]> {
        let mut collector = RangeCollector::default();
        Self::visit_layout(bx, &mut collector, layout, Size::ZERO, imprecise);
        collector.collect()
    }
}

/// Collects the ranges within a type that are covered by `UnsafeCell`.
struct UnsafeCellRanges;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> PerByteTracking<'a, 'tcx, Bx> for UnsafeCellRanges {
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        ty.is_freeze(bx.tcx(), bx.cx().typing_env())
    }

    fn contains(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        let tcx = bx.tcx();
        match ty.kind() {
            ty::Adt(adt, _) => Some(adt.did()) == tcx.lang_items().unsafe_cell_type(),
            _ => false,
        }
    }
}

/// Collects the ranges within a type that are covered by `UnsafePinned`.
struct UnsafePinnedRanges;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> PerByteTracking<'a, 'tcx, Bx> for UnsafePinnedRanges {
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        ty.is_unpin(bx.tcx(), bx.typing_env()) && ty.is_unsafe_unpin(bx.tcx(), bx.typing_env())
    }

    fn contains(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        let tcx = bx.tcx();
        match ty.kind() {
            ty::Adt(adt, _) => Some(adt.did()) == tcx.lang_items().unsafe_pinned_type(),
            _ => false,
        }
    }
}

/// Helper for collecting a list of ranges within the size of a type,
/// such that adjacent ranges are merged.
struct RangeCollector {
    /// The start of the currently accumulating
    /// range that satisfies the predicate.
    cursor: Size,

    /// The size of the currently accumulating range
    /// that satisfies the predicate.
    acc_size: Size,

    /// A list of accumulated ranges.
    ranges: Vec<[Size; 2]>,
}

impl Default for RangeCollector {
    fn default() -> Self {
        Self { cursor: Size::ZERO, acc_size: Size::ZERO, ranges: vec![] }
    }
}

impl RangeCollector {
    /// Extend the current range.
    fn extend(&mut self, size: Size) {
        self.acc_size += size;
    }

    /// Move the collector forward to the given offset, recording the
    /// current range if this leaves a gap.
    fn advance(&mut self, next_cursor: Size) {
        assert!(next_cursor >= self.cursor + self.acc_size);
        if self.cursor + self.acc_size != next_cursor {
            if self.acc_size > Size::ZERO {
                self.ranges.push([self.cursor, self.acc_size]);
                self.acc_size = Size::ZERO;
            }
            self.cursor = next_cursor;
        }
    }

    /// Consumes the collector, returning all recorded ranges.
    fn collect(mut self) -> Vec<[Size; 2]> {
        if self.acc_size > Size::ZERO {
            self.ranges.push([self.cursor, self.acc_size]);
        }
        self.ranges
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    /// Retags the pointers within an [`OperandRef`].
    pub(crate) fn codegen_retag_operand(
        &mut self,
        bx: &mut Bx,
        operand: OperandRef<'tcx, Bx::Value>,
        is_fn_entry: bool,
    ) -> OperandRef<'tcx, Bx::Value> {
        if let OperandValue::Ref(place_ref) = operand.val {
            let place_ref = place_ref.with_type(operand.layout);
            self.codegen_retag_place(bx, place_ref, is_fn_entry);
        } else if let Some(plan) = RetagPlan::<Bx::Value>::build(bx, operand.layout, is_fn_entry) {
            let mut builder = OperandRefBuilder::from_existing(operand);
            self.retag_operand(bx, &plan, operand, &mut builder, Size::ZERO);
            return builder.build(bx.cx());
        }
        operand
    }

    /// Retags the pointers within a [`PlaceRef`].
    pub(crate) fn codegen_retag_place(
        &mut self,
        bx: &mut Bx,
        place_ref: PlaceRef<'tcx, Bx::Value>,
        is_fn_entry: bool,
    ) {
        if let Some(plan) = RetagPlan::<Bx::Value>::build(bx, place_ref.layout, is_fn_entry) {
            self.retag_place(bx, &plan, place_ref);
        }
    }

    fn retag_operand(
        &mut self,
        bx: &mut Bx,
        plan: &RetagPlan<Bx::Value>,
        curr_operand: OperandRef<'tcx, Bx::Value>,
        builder: &mut OperandRefBuilder<'tcx, Bx::Value>,
        offset: Size,
    ) {
        match plan {
            RetagPlan::EmitRetag(info) => {
                let (pointer, _) = curr_operand.val.pointer_parts();
                let retagged_pointer = bx.retag_reg(pointer, info);
                builder.update_imm(offset, retagged_pointer);
            }
            RetagPlan::Recurse { field_plans, variant_plans } => {
                let layout = curr_operand.layout;
                for (ix, plan) in field_plans {
                    let inner_offset = layout.fields.offset(ix.as_usize());
                    let field_offset = offset + inner_offset;

                    let field_value = curr_operand.extract_field(self, bx, ix.as_usize());
                    self.retag_operand(bx, &plan, field_value, builder, field_offset);
                }

                if !variant_plans.is_empty() {
                    let discr_ty = layout.ty.discriminant_ty(bx.tcx());
                    let discr_val = curr_operand.codegen_get_discr(self, bx, discr_ty);

                    if let Some(val) = bx.const_to_opt_u128(discr_val, false) {
                        let ix = VariantIdx::from_usize(val as usize);
                        if let Some(plan) = variant_plans.get(&ix) {
                            let mut variant_op = curr_operand;
                            variant_op.layout = curr_operand.layout.for_variant(bx, ix);

                            self.retag_operand(bx, plan, variant_op, builder, offset);
                        }
                    } else {
                        // The value of this operand will be different depending on which variant
                        // we have. To handle this, we create a temporary place to store the operand.
                        let scratch = PlaceRef::alloca(bx, curr_operand.layout);
                        scratch.storage_live(bx);
                        curr_operand.store_with_annotation(bx, scratch);

                        // We retag the contents of the place
                        self.retag_variants(bx, scratch, discr_val, variant_plans);

                        // Afterward, we load the now-updated operand and end the lifetime of the place.
                        let updated_op = bx.load_operand(scratch);
                        scratch.storage_dead(bx);

                        // The `curr_operand` may be a field or variant of the original operand that we are updating
                        // using the `builder.` We need to apply the updates from `updated_op` at an offset relative to
                        // the current `offset` within the parent operand being retagged.
                        match updated_op.val {
                            OperandValue::ZeroSized | OperandValue::Ref(_) => {}
                            OperandValue::Immediate(imm) => builder.update_imm(offset, imm),
                            OperandValue::Pair(fst, snd) => {
                                builder.update_imm(offset, fst);
                                builder.update_imm(offset + Size::from_bytes(1), snd)
                            }
                        }
                    }
                }
            }
        }
    }

    fn retag_place(
        &mut self,
        bx: &mut Bx,
        plan: &RetagPlan<Bx::Value>,
        place: PlaceRef<'tcx, Bx::Value>,
    ) {
        match plan {
            RetagPlan::EmitRetag(info) => {
                bx.retag_mem(place.val.llval, info);
            }
            RetagPlan::Recurse { field_plans, variant_plans } => {
                for (ix, plan) in field_plans {
                    let field_place = place.project_field(bx, ix.as_usize());
                    self.retag_place(bx, &plan, field_place);
                }
                if !variant_plans.is_empty() {
                    let consumed = bx.load_operand(place);
                    let discr_ty = place.layout.ty.discriminant_ty(bx.tcx());
                    let discr_val = consumed.codegen_get_discr(self, bx, discr_ty);
                    self.retag_variants(bx, place, discr_val, variant_plans);
                }
            }
        }
    }

    /// Retags each variant of a [`PlaceRef`] with the given discriminant.
    fn retag_variants(
        &mut self,
        bx: &mut Bx,
        place: PlaceRef<'tcx, Bx::Value>,
        discr: Bx::Value,
        variant_plans: &FxIndexMap<VariantIdx, RetagPlan<Bx::Value>>,
    ) {
        let layout = place.layout;

        let root_block = bx.llbb();
        let mut variant_blocks = Vec::with_capacity(variant_plans.len());
        let join_block = bx.append_sibling_block("retag_join");

        for (ix, plan) in variant_plans {
            let variant_discr = layout.ty.discriminant_for_variant(bx.tcx(), *ix);
            let variant_discr_val = variant_discr.expect("Invalid variant index.").val;

            let variant_block = bx.append_sibling_block("retag_variant");
            bx.switch_to_block(variant_block);

            let variant_place = place.project_downcast(bx, *ix);
            self.retag_place(bx, plan, variant_place);
            // If the variant contains another variant, then the current block
            // will be different than the one that we created above. We want this
            // block to jump to the terminator block.
            variant_blocks.push((variant_discr_val, bx.llbb()));
            bx.br(join_block);
        }

        bx.switch_to_block(root_block);
        bx.switch(discr, join_block, variant_blocks.into_iter());
        bx.switch_to_block(join_block);
    }
}
