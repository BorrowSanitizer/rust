//! Support for emitting retags as function calls.
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

use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::interpret::Allocation;
use rustc_middle::ty;
use rustc_middle::ty::Mutability;
use rustc_middle::ty::data_structures::IndexMap;
use rustc_middle::ty::layout::HasTypingEnv;

use super::{BuilderMethods, FunctionCx};
use crate::mir::operand::{OperandRef, OperandRefBuilder, OperandValue};
use crate::mir::place::PlaceRef;
use crate::mir::{Ty, TyAndLayout};
use crate::traits::{BaseTypeCodegenMethods, CodegenMethods};
use crate::{RetagFlags, RetagInfo};

/// A description of the pointers within a type that are affected by a retag.
#[derive(Debug)]
enum RetagPlan<V> {
    /// Indicates that a pointer should be retagged.
    EmitRetag(RetagInfo<V>),

    /// Indicates that one or more fields or variants of this type
    /// contain pointers that need to be retagged.
    Recurse {
        field_plans: IndexMap<FieldIdx, RetagPlan<V>>,
        variant_plans: IndexMap<VariantIdx, RetagPlan<V>>,
    },
}

impl<V> RetagPlan<V> {
    /// A helper function to move a [`RetagPlan`] into a particular field.
    fn for_field(plan: RetagPlan<V>, ix: FieldIdx) -> Self {
        let (mut field_plans, variant_plans) = (IndexMap::default(), IndexMap::default());
        field_plans.insert(ix, plan);
        RetagPlan::Recurse { field_plans, variant_plans }
    }
}

impl<'a, 'tcx, V> RetagPlan<V> {
    /// Attempts to create a [`RetagPlan`] for a place or operand with the given layout.
    fn build<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
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
            ty::Adt(adt, _) if adt.is_box() => Self::visit_box(bx, fx, layout, is_fn_entry),

            _ => Self::walk_value(bx, fx, layout, is_fn_entry),
        }
    }

    /// Recurses through the fields and variants of a value in memory order to create a [`RetagPlan`].
    fn walk_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        let indices: Vec<FieldIdx> = match &layout.fields {
            FieldsShape::Union(_) | FieldsShape::Primitive => vec![],
            _ => layout.fields.index_by_increasing_offset().map(FieldIdx::from_usize).collect(),
        };

        let fields: Vec<(FieldIdx, RetagPlan<Bx::Value>)> = indices
            .iter()
            .filter_map(|ix| {
                let field_layout = layout.field(bx, ix.as_usize());
                Self::build(bx, fx, field_layout, is_fn_entry).map(|plan| (*ix, plan))
            })
            .collect();
        let variants: Vec<(VariantIdx, RetagPlan<Bx::Value>)> = match &layout.variants {
            Variants::Multiple { variants, .. } => variants
                .indices()
                .filter_map(|vix| {
                    let variant_layout = layout.for_variant(bx, vix);
                    Self::build(bx, fx, variant_layout, is_fn_entry).map(|plan| (vix, plan))
                })
                .collect(),
            Variants::Single { .. } | Variants::Empty => vec![],
        };

        (!fields.is_empty() || !variants.is_empty()).then(|| RetagPlan::Recurse {
            field_plans: fields.into_iter().collect(),
            variant_plans: variants.into_iter().collect(),
        })
    }

    /// Emits a retag for a `Box`.
    fn visit_box<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        ptr_layout: TyAndLayout<'tcx>,
        is_fn_entry: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        assert!(ptr_layout.ty.is_box());
        assert_eq!(ptr_layout.fields.count(), 2, "`Box` must have exactly 2 fields");
        let mut fields = vec![];

        // Only retag the inner pointer of a `Box` if it came from the global allocator.
        // We need special handling here because we are retagging a raw pointer, which would
        // usually be skipped.
        if ptr_layout.ty.is_box_global(bx.tcx()) {
            let boxed_ty = ptr_layout.ty.expect_boxed_ty();
            let boxed_layout = bx.layout_of(boxed_ty);
            if let Some(mut plan) = Self::emit_retag(bx, boxed_layout, None, is_fn_entry) {
                // `Unique<T>`
                let unique = ptr_layout.field(bx, 0);
                plan = RetagPlan::for_field(plan, FieldIdx::ZERO);

                // `NonNull<T>`
                let nonnull = unique.field(bx, 0);
                plan = RetagPlan::for_field(plan, FieldIdx::ZERO);

                // `pattern_type!(*mut T + ..)`
                let pattern = nonnull.field(bx, 0);
                plan = RetagPlan::for_field(plan, FieldIdx::ZERO);

                // `*mut T`
                let ptr = pattern.field(bx, 0);
                assert_eq!(ptr.ty.builtin_deref(true), Some(boxed_ty));
                fields.push((FieldIdx::ZERO, plan));
            }
        }

        // We always try to retag the second field (the allocator)
        let field_layout = ptr_layout.field(bx, 1);
        if let Some(plan) = Self::build(bx, fx, field_layout, is_fn_entry) {
            fields.push((FieldIdx::ONE, plan));
        }

        (!fields.is_empty()).then(|| RetagPlan::Recurse {
            field_plans: fields.into_iter().collect(),
            variant_plans: IndexMap::default(),
        })
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
            // Everything is covered by `UnsafePinned`.
            let all_pinned = matches!(
                pin_ranges.as_slice(),
                [[Size::ZERO, size]] if *size == pointee_layout.size,
            );
            // We can't find any `UnsafePinned`, but the type is still
            // `!Unpin` or `!UnsafeUnpin`.
            let implicitly_pinned = pin_ranges.is_empty() && !is_unpin;

            if all_pinned || implicitly_pinned {
                return None;
            }
        };

        let im_ranges = UnsafeCellRanges::collect(bx, pointee_layout, opts.no_precise_im);

        let mut flags = RetagFlags::empty();
        flags.set(RetagFlags::IS_PROTECTED, is_protected);
        flags.set(RetagFlags::IS_MUTABLE, is_mutable);
        flags.set(RetagFlags::IS_BOX, is_box);

        // We need to track `Freeze` separately from `UnsafeCellRanges` so that we can
        // handle ZSTs, which still need to be treated as interior mutable (e.g. `UnsafeCell<()>`).
        flags.set(RetagFlags::IS_FREEZE, is_freeze);

        Some(RetagPlan::EmitRetag(RetagInfo {
            size: pointee_layout.size,
            im_layout: Self::alloc_ranges(bx, im_ranges),
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
        if ranges.is_empty() {
            return bx.const_null(bx.type_ptr());
        }

        let bytes: Vec<u8> =
            ranges.iter().flatten().flat_map(|u| u.bytes_usize().to_ne_bytes()).collect();

        let align = tcx.data_layout.ptr_sized_integer().align(&tcx.data_layout).abi;

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

        // Optionally, we can treat a type that contains the type we are looking for
        // as being equivalent to that type. For example, we would treat an entire type
        // as interior mutable if it contains an `UnsafeCell` at any offset.
        if imprecise {
            return collector.extend(layout.size);
        }

        let union_or_primitive =
            matches!(layout.fields, FieldsShape::Union(..) | FieldsShape::Primitive);
        let has_multiple_variants = matches!(layout.variants, Variants::Multiple { .. });

        if Self::contains(bx, layout.ty) || union_or_primitive || has_multiple_variants {
            collector.extend(layout.size);
        } else {
            let indices: Vec<FieldIdx> = match &layout.fields {
                FieldsShape::Union(_) | FieldsShape::Primitive => vec![],
                _ => layout.fields.index_by_increasing_offset().map(FieldIdx::from_usize).collect(),
            };

            for ix in indices {
                // We need to find the offset for this field relative
                // to the entire type, not just the current aggregate
                // that we are visiting here.
                let field_offset = layout.fields.offset(ix.as_usize());
                let layout_offset = field_offset + base_offset;
                collector.advance(layout_offset);

                let field = layout.field(bx, ix.as_usize());
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
    acc_offset: Size,

    /// A list of accumulated ranges.
    ranges: Vec<[Size; 2]>,
}

impl Default for RangeCollector {
    fn default() -> Self {
        Self { cursor: Size::ZERO, acc_offset: Size::ZERO, ranges: vec![] }
    }
}

impl RangeCollector {
    /// Extend the current range.
    fn extend(&mut self, size: Size) {
        self.acc_offset += size;
    }

    /// Move the collector forward to the given offset, recording the
    /// current range if this leaves a gap.
    fn advance(&mut self, next_cursor: Size) {
        assert!(next_cursor >= self.cursor + self.acc_offset);
        if self.cursor + self.acc_offset != next_cursor {
            if self.acc_offset > Size::ZERO {
                self.ranges.push([self.cursor, self.acc_offset]);
                self.acc_offset = Size::ZERO;
            }
            self.cursor = next_cursor;
        }
    }

    /// Consumes the collector, returning all recorded ranges.
    fn collect(mut self) -> Vec<[Size; 2]> {
        if self.acc_offset > Size::ZERO {
            self.ranges.push([self.cursor, self.acc_offset]);
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
        } else if let Some(plan) =
            &RetagPlan::<Bx::Value>::build(bx, self, operand.layout, is_fn_entry)
        {
            let mut builder = OperandRefBuilder::from_existing(operand);
            self.retag_operand(bx, plan, operand, &mut builder, Size::ZERO);
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
        if let Some(plan) = &RetagPlan::<Bx::Value>::build(bx, self, place_ref.layout, is_fn_entry)
        {
            self.retag_place(bx, plan, place_ref);
        }
    }

    fn retag_operand(
        &mut self,
        bx: &mut Bx,
        plan: &RetagPlan<Bx::Value>,
        operand: OperandRef<'tcx, Bx::Value>,
        builder: &mut OperandRefBuilder<'tcx, Bx::Value>,
        offset: Size,
    ) {
        match plan {
            RetagPlan::EmitRetag(info) => {
                let (pointer, _) = operand.val.pointer_parts();
                let retagged_pointer = bx.retag_reg(pointer, info);
                builder.update_imm(offset, retagged_pointer);
            }
            RetagPlan::Recurse { field_plans, variant_plans } => {
                let layout = operand.layout;
                for (ix, plan) in field_plans.iter() {
                    let inner_offset = layout.fields.offset(ix.as_usize());
                    let field_offset = offset + inner_offset;

                    let field_value = operand.extract_field(self, bx, ix.as_usize());
                    self.retag_operand(bx, &plan, field_value, builder, field_offset);
                }

                if !variant_plans.is_empty() {
                    let discr_ty = layout.ty.discriminant_ty(bx.tcx());
                    let discr_val = operand.codegen_get_discr(self, bx, discr_ty);
                    if let Some(val) = bx.const_to_opt_u128(discr_val, false) {
                        let ix = VariantIdx::from_usize(val as usize);
                        if let Some(plan) = variant_plans.get(&ix) {
                            let mut variant_op = operand;
                            variant_op.layout = operand.layout.for_variant(bx, ix);
                            self.retag_operand(bx, plan, variant_op, builder, offset);
                        }
                    } else {
                        let scratch = PlaceRef::alloca(bx, layout);
                        scratch.storage_live(bx);

                        self.retag_variants(bx, scratch, discr_val, variant_plans);

                        let op = bx.load_operand(scratch);
                        scratch.storage_dead(bx);

                        *builder = OperandRefBuilder::from_existing(op)
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
                for (ix, plan) in field_plans.iter() {
                    let field_place = place.project_field(bx, ix.as_usize());
                    self.retag_place(bx, &plan, field_place);
                }
                if !variant_plans.is_empty() {
                    let layout = place.layout;
                    let consumed = bx.load_operand(place);
                    let discr_ty = layout.ty.discriminant_ty(bx.tcx());
                    let discr_val = consumed.codegen_get_discr(self, bx, discr_ty);
                    self.retag_variants(bx, place, discr_val, variant_plans);
                }
            }
        }
    }

    fn retag_variants(
        &mut self,
        bx: &mut Bx,
        place: PlaceRef<'tcx, Bx::Value>,
        discr: Bx::Value,
        variant_plans: &IndexMap<VariantIdx, RetagPlan<Bx::Value>>,
    ) {
        let layout = place.layout;

        let root_block = bx.llbb();
        let mut variant_blocks: Vec<(u128, Bx::BasicBlock)> = vec![];
        let terminator_block = bx.append_sibling_block("v_t");

        for (ix, plan) in variant_plans.iter() {
            let variant_discr_val =
                layout.ty.discriminant_for_variant(bx.tcx(), *ix).expect("Invalid variant.").val;

            let variant_block = bx.append_sibling_block("v");
            bx.switch_to_block(variant_block);

            let variant_place = place.project_downcast(bx, *ix);
            self.retag_place(bx, plan, variant_place);
            // If the variant contains another variant, then the current block
            // will be different than the one that we created above. We want this
            // block to jump to the terminator block.
            variant_blocks.push((variant_discr_val, bx.llbb()));
            bx.br(terminator_block);
        }

        bx.switch_to_block(root_block);
        bx.switch(discr, terminator_block, variant_blocks.drain(..));
        bx.switch_to_block(terminator_block);
    }
}
