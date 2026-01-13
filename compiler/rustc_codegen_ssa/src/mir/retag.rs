//! Support for emitting retag intrinsics, which are used to model Rust's aliasing
//! semantics within lower-level representations.
use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::interpret::Allocation;
use rustc_middle::ty::Mutability;
use rustc_middle::ty::data_structures::IndexMap;
use rustc_middle::ty::layout::HasTypingEnv;
use rustc_middle::{bug, ty};

use super::{BuilderMethods, FunctionCx};
use crate::mir::operand::{OperandRef, OperandRefBuilder, OperandValue};
use crate::mir::place::PlaceRef;
use crate::mir::{Ty, TyAndLayout};
use crate::traits::{BaseTypeCodegenMethods, CodegenMethods};
use crate::{RetagFlags, RetagInfo};

/// A description of the pointers within a type that need to be retagged.
#[derive(Debug)]
enum RetagPlan<V> {
    /// Indicates that a pointer should be retagged.
    EmitRetag(RetagInfo<V>),
    /// Indicates that one or more fields or variants of this type
    /// contain pointers that need to be retagged.
    Recurse {
        fields: IndexMap<FieldIdx, RetagPlan<V>>,
        variants: IndexMap<VariantIdx, RetagPlan<V>>,
    },
}

impl<'a, 'tcx, V> RetagPlan<V> {
    /// Attempts to create a [`RetagPlan`] for a value with the given layout.
    fn build<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        is_protected: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        // If the value being retagged is smaller than a pointer, then it can't contain any
        // pointers we need to retag, so we can stop recrsion early. This optimization is crucial
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
                Self::emit_retag(bx, pointee_layout, Some(mt), is_protected)
            }
            &ty::RawPtr(_, _) => None,
            // `Box`` needs special handling, since the innermost pointer is what gets retagged, but
            // though the outermost `Box` is what determines the permission that gets created.
            ty::Adt(adt, _) if adt.is_box() => Self::visit_box(bx, fx, layout, is_protected),

            _ => Self::walk_value(bx, fx, layout, is_protected),
        }
    }

    /// Recurses through the fields and variants of a value to create a [`RetagPlan`].
    fn walk_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        is_protected: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        let (fields, variants) = if let Some(def) = layout.ty.ty_adt_def()
            && def.is_unsafe_cell()
        {
            let field_layout = layout.field(bx.cx(), FieldIdx::ZERO.as_usize());
            let fields: Vec<(FieldIdx, RetagPlan<Bx::Value>)> =
                Self::build(bx, fx, field_layout, is_protected)
                    .map(|plan| vec![(FieldIdx::ZERO, plan)])
                    .unwrap_or_default();
            (fields, Vec::new())
        } else {
            let indices: Vec<FieldIdx> = match &layout.fields {
                FieldsShape::Union(_) | FieldsShape::Primitive => Vec::new(),
                FieldsShape::Arbitrary { in_memory_order, .. } => {
                    in_memory_order.iter().copied().collect()
                }
                FieldsShape::Array { .. } => {
                    layout.fields.index_by_increasing_offset().map(FieldIdx::from_usize).collect()
                }
            };

            let fields: Vec<(FieldIdx, RetagPlan<Bx::Value>)> = indices
                .iter()
                .filter_map(|idx| {
                    let field_layout = layout.field(bx.cx(), idx.as_usize());
                    Self::build(bx, fx, field_layout, is_protected).map(|plan| (*idx, plan))
                })
                .collect();
            let variants: Vec<(VariantIdx, RetagPlan<Bx::Value>)> = match &layout.variants {
                Variants::Multiple { variants, .. } => variants
                    .indices()
                    .filter_map(|vidx| {
                        let variant_layout = layout.for_variant(bx.cx(), vidx);
                        Self::build(bx, fx, variant_layout, is_protected).map(|plan| (vidx, plan))
                    })
                    .collect(),
                Variants::Single { .. } | Variants::Empty => Vec::new(),
            };
            (fields, variants)
        };

        (!fields.is_empty() || !variants.is_empty()).then(|| RetagPlan::Recurse {
            fields: fields.into_iter().collect(),
            variants: variants.into_iter().collect(),
        })
    }

    /// Emits a [`RetagPlan::EmitRetag`] for a `Box`.
    fn visit_box<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        is_protected: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");
        let mut fields = Vec::new();

        // Only retag the inner pointer of a `Box` if it came from the global allocator.
        // We need special handling here because we are retagging a raw pointer, which would
        // usually be skipped.
        if layout.ty.is_box_global(bx.tcx()) {
            // 0: `Unique<T>`
            let unique = layout.field(bx, FieldIdx::ZERO.into());

            // 0: `NonNull<T>`, 1: `PhantomData<T>`
            assert_eq!(unique.fields.count(), 2);

            // 1: `PhantomData<T>`
            let phantom = unique.field(bx, FieldIdx::ONE.into());
            assert!(
                phantom.ty.ty_adt_def().is_some_and(|adt| adt.is_phantom_data()),
                "2nd field of `Unique` should be PhantomData but is {:?}",
                phantom.ty,
            );

            // 0: `NonNull<T>`
            let nonnull_ptr: rustc_abi::TyAndLayout<'_, _> =
                unique.field(bx, FieldIdx::ZERO.into());
            assert_eq!(nonnull_ptr.fields.count(), 1);

            // 0: `pattern_type!(*mut T + ..)`
            let pattern_ty = nonnull_ptr.field(bx, FieldIdx::ZERO.into());
            let pattern_ty = fx.monomorphize(pattern_ty.ty);

            let pointee_layout = if let ty::Pat(ptr_ty, _) = pattern_ty.kind() {
                let pointee_ty = ptr_ty.builtin_deref(true).unwrap();
                bx.layout_of(pointee_ty)
            } else {
                bug!("expected a `!null` pattern");
            };
            if let Some(mut plan) = Self::emit_retag(bx, pointee_layout, None, is_protected) {
                for idx in &[FieldIdx::ZERO].repeat(1) {
                    let (mut fields, variants) = (IndexMap::default(), IndexMap::default());
                    fields.insert(*idx, plan);
                    plan = RetagPlan::Recurse { fields, variants };
                }
                fields.push((FieldIdx::ZERO, plan));
            }
        }

        // We always try to retag the second field (the allocator)
        let field_layout = layout.field(bx.cx(), FieldIdx::ONE.as_usize());

        if let Some(plan) = Self::build(bx, fx, field_layout, is_protected) {
            fields.push((FieldIdx::ONE, plan));
        }

        (!fields.is_empty()).then(|| RetagPlan::Recurse {
            fields: fields.into_iter().collect(),
            variants: IndexMap::default(),
        })
    }

    /// Attempts to creates a [`RetagPlan::EmitRetag`] for a pointer with the given layout.
    /// Returns `None` for mutable pointers to types that are entirely covered by `UnsafePinned`,
    /// for which retags are a noop.
    fn emit_retag<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        pointee_layout: TyAndLayout<'tcx>,
        ptr_kind: Option<Mutability>,
        is_protected: bool,
    ) -> Option<RetagPlan<Bx::Value>> {
        let codegen_opts = bx.tcx().sess.opts.unstable_opts.codegen_emit_retag.unwrap_or_default();

        let pointee_ty = pointee_layout.ty;
        let pin_ranges =
            UnsafePinnedRanges::collect(bx, pointee_layout, codegen_opts.no_precise_pin);

        let is_mutable = matches!(ptr_kind, Some(Mutability::Mut) | None);

        if is_mutable {
            // If everything is `UnsafePinned`, or we have a ZST, then skip retagging.
            let pinned_size =
                pin_ranges.first().and_then(|elem| elem.get(1)).copied().unwrap_or(Size::ZERO);
            if pinned_size == pointee_layout.size {
                return None;
            }
        }

        let im_ranges = UnsafeCellRanges::collect(bx, pointee_layout, codegen_opts.no_precise_im);

        let mut flags = RetagFlags::empty();
        flags.set(RetagFlags::IS_PROTECTED, is_protected);
        flags.set(RetagFlags::IS_MUTABLE, is_mutable);
        flags.set(RetagFlags::IS_FREEZE, pointee_ty.is_freeze(bx.tcx(), bx.typing_env()));
        flags.set(RetagFlags::IS_BOX, ptr_kind.is_none());

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
        let alloc_id = tcx.reserve_and_set_memory_alloc(const_alloc);

        let global_alloc = tcx.global_alloc(alloc_id);
        let global_mem = global_alloc.unwrap_memory();
        bx.cx().static_addr_of(global_mem, None)
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    /// Retags the pointers within an [`OperandRef`].
    pub(crate) fn codegen_retag_operand(
        &mut self,
        bx: &mut Bx,
        op: OperandRef<'tcx, Bx::Value>,
        is_protected: bool,
    ) -> OperandRef<'tcx, Bx::Value> {
        if let OperandValue::Ref(place_ref) = op.val {
            let place_ref = place_ref.with_type(op.layout);
            self.codegen_retag_place(bx, place_ref, is_protected);
        } else if let Some(plan) = RetagPlan::<Bx::Value>::build(bx, self, op.layout, is_protected)
        {
            return self.retag(bx, plan, op);
        }
        op
    }

    /// Retags the pointers within a [`PlaceRef`].
    pub(crate) fn codegen_retag_place(
        &mut self,
        bx: &mut Bx,
        place_ref: PlaceRef<'tcx, Bx::Value>,
        is_protected: bool,
    ) {
        if let Some(plan) = RetagPlan::<Bx::Value>::build(bx, self, place_ref.layout, is_protected)
        {
            self.retag(bx, plan, place_ref);
        }
    }

    fn retag<R: Retagable<'a, 'tcx, Bx>>(
        &mut self,
        bx: &mut Bx,
        plan: RetagPlan<Bx::Value>,
        value: R,
    ) -> R {
        let mut retag_cx = value.retag_cx();
        self.retag_inner(bx, &mut retag_cx, &plan, value, Size::ZERO);
        retag_cx.resolve(bx)
    }

    fn retag_inner<R: Retagable<'a, 'tcx, Bx>>(
        &mut self,
        bx: &mut Bx,
        retag_cx: &mut R::Cx,
        plan: &RetagPlan<Bx::Value>,
        value: R,
        cursor: Size,
    ) {
        match plan {
            RetagPlan::EmitRetag(info) => {
                let retagged_value = value.retag(bx, *info);
                retag_cx.retag(cursor, retagged_value)
            }
            RetagPlan::Recurse { fields, variants } => {
                for (ix, field_plan) in fields.iter() {
                    let field_cursor = value.layout().fields.offset((*ix).as_usize()) + cursor;
                    let field_value = value.project_field(bx, self, *ix);
                    self.retag_inner(bx, retag_cx, field_plan, field_value, field_cursor);
                }

                if !variants.is_empty() {
                    let operand = value.load_operand(bx);
                    let discr_ty = value.layout().ty.discriminant_ty(bx.tcx());
                    let discr_val = operand.codegen_get_discr(self, bx, discr_ty);

                    // If the discriminant is a constant, then we can just downcast and avoid branching.
                    if let Some(val) = bx.const_to_opt_u128(discr_val, false) {
                        let ix = VariantIdx::from_usize(val as usize);
                        let variant_value = value.project_downcast(bx, ix);
                        if let Some(variant_plan) = variants.get(&ix) {
                            self.retag_inner(bx, retag_cx, variant_plan, variant_value, cursor);
                        }
                    } else {
                        // Otherwise, we need a block for each variant.
                        let root_block = bx.llbb();
                        let mut variant_blocks: Vec<(u128, Bx::BasicBlock)> = vec![];

                        // Each variant's block should arrive at the same terminator.
                        let terminator_block = bx.append_sibling_block("v_t");

                        // Each variant may update the current value in different ways. We collect a value context
                        // for each block, and then merge these contexts in the terminator, producing one or more
                        // phi nodes for operands.
                        let mut updates: Vec<(Bx::BasicBlock, R::Cx)> =
                            vec![(root_block, (*retag_cx).clone())];

                        for (ix, variant_plan) in variants.iter() {
                            let discr_val = value
                                .layout()
                                .ty
                                .discriminant_for_variant(bx.tcx(), *ix)
                                .expect("Invalid variant.")
                                .val;

                            let variant_block = bx.append_sibling_block("v");
                            bx.switch_to_block(variant_block);

                            let variant_value = value.project_downcast(bx, *ix);
                            let mut variant_cx = (*retag_cx).clone();

                            self.retag_inner(
                                bx,
                                &mut variant_cx,
                                variant_plan,
                                variant_value,
                                cursor,
                            );
                            // If the variant contains another variant, then the current block
                            // will be different than the one that we created above. We want this block to jump
                            // to the terminator block.
                            updates.push((bx.llbb(), variant_cx));
                            bx.br(terminator_block);

                            // We need to record the new variant block that we created so that we can switch
                            // to it from the root block.
                            variant_blocks.push((discr_val, variant_block))
                        }

                        bx.switch_to_block(root_block);
                        bx.switch(discr_val, terminator_block, variant_blocks.drain(..));
                        bx.switch_to_block(terminator_block);

                        retag_cx.phi(bx, updates);
                    }
                }
            }
        }
    }
}

/// A visitor trait that collects the ranges within a layout that satisfy a given predicate.
trait PerByteTracking<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> {
    /// Returns `Some(true)` if the range containing this type can be excluded.
    /// This tells us that [`PerByteTracking::contains`] is false for every
    /// field or variant without having to recurse any further into the layout of the type.
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool;
    /// The range containing this type should be included.
    fn contains(bx: &mut Bx, ty: Ty<'tcx>) -> bool;

    fn visit_layout(
        bx: &mut Bx,
        collector: &mut RangeCollector,
        layout: TyAndLayout<'tcx>,
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
                FieldsShape::Union(_) | FieldsShape::Primitive => Vec::new(),
                FieldsShape::Arbitrary { in_memory_order, .. } => {
                    in_memory_order.iter().copied().collect()
                }
                FieldsShape::Array { .. } => {
                    layout.fields.index_by_increasing_offset().map(FieldIdx::from_usize).collect()
                }
            };
            for idx in indices {
                collector.advance(layout.fields.offset(idx.as_usize()));
                let field = layout.field(bx.cx(), idx.as_usize());
                Self::visit_layout(bx, collector, field, imprecise);
            }
        }
    }

    /// Collects the ranges within a type that satisfy the given predicate. A range is a
    /// pair of [`Size`], representing the offset and width, respectively.
    fn collect(bx: &mut Bx, layout: TyAndLayout<'tcx>, imprecise: bool) -> Vec<[Size; 2]> {
        let mut collector = RangeCollector::default();
        Self::visit_layout(bx, &mut collector, layout, imprecise);
        collector.collect()
    }
}

/// Collects the ranges within a type that are covered by `UnsafeCell`.
struct UnsafeCellRanges;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> PerByteTracking<'a, 'tcx, Bx> for UnsafeCellRanges {
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        // If a type is `Freeze`, then it does not contain `UnsafeCell`
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
        // If a type is `UnsafeUnpin`, then it does not contain `UnsafePinned`
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
    /// The start of the current range
    /// being examined
    cursor: Size,
    /// The start of the previous range that
    /// satisfies the predicate.
    prev_cursor: Size,
    /// The size of the previous range that
    /// satisfies the predicate.
    acc_offset: Size,
    /// A list of accumulated ranges.
    ranges: Vec<[Size; 2]>,
}

impl Default for RangeCollector {
    fn default() -> Self {
        Self {
            prev_cursor: Size::ZERO,
            cursor: Size::ZERO,
            acc_offset: Size::ZERO,
            ranges: Vec::new(),
        }
    }
}

impl RangeCollector {
    /// Extend the current range.
    fn extend(&mut self, size: Size) {
        self.acc_offset += size;
    }

    /// Move the collector forward to the given offset, recording the
    /// current range if this leaves a gap between the start of the last
    /// range and the current offset.
    fn advance(&mut self, offset: Size) {
        self.cursor = offset;
        if self.prev_cursor + self.acc_offset != offset {
            if self.acc_offset > Size::ZERO {
                self.ranges.push([self.prev_cursor, self.acc_offset]);
                self.acc_offset = Size::ZERO;
            }
            self.prev_cursor = offset;
        }
    }

    /// Consumes the collector, returning all recorded ranges.
    fn collect(mut self) -> Vec<[Size; 2]> {
        if self.acc_offset > Size::ZERO {
            self.ranges.push([self.prev_cursor, self.acc_offset]);
        }
        self.ranges
    }
}

/// A value containing pointers that can be retagged (in practice, this is either an [`OperandRef`] or a [`PlaceRef`]).
/// At this level, a pointer's provenance is inseparable from its address, so retagging a pointer within a place would
/// require loading it, performing the retag, and then storing the retagged pointer back to where it came from. This final
/// `store` is undefined behavior if the place that we are retagging is a pointer that has LLVM's `readonly` metadata, or
/// any equivalent annotation. To avoid this, we use two forms of retag. The first, `__rust_retag_reg`, is used for operands,
/// which are already loaded into registers. It returns an alias with the same address, but new provenance. The second form,
///  `__rust_retag_mem`, does not create an alias. It receive a pointer to the place that contains the pointer that needs to be
/// retagged. BorrowSanitizer inserts the necessary `load` and `store` operations to update only the pointer's provenance
/// without inserting a direct `store` to the place.
trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    /// When we are retagging an [`OperandRef`], we use an [`OperandRefBuilder`]
    /// replaced retagged pointers (e.g `%new_ptr = __rust_retag_reg(%old_ptr, ..)`).
    type Cx: RetagCx<'a, 'tcx, Bx, Self>;
    /// Creates a new context object that tracks updates to the current value.
    fn retag_cx(&self) -> Self::Cx;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn layout(&self) -> TyAndLayout<'tcx>;

    fn load_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    /// Retags the current value, producing a new value.
    /// This is a noop for [`PlaceRef`].
    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> Self;
}

/// A context used to collect the updates to a [`Retagable`] value.
trait RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>>:
    Sized + Clone
{
    /// Resolves multiple retagged variants of a value into its final form.
    fn phi(&mut self, bx: &mut Bx, branches: Vec<(Bx::BasicBlock, Self)>);

    /// Applies the updates that have been collected during traveral to the initial
    /// "base" value being retagged.
    fn resolve(&self, bx: &mut Bx) -> R;

    /// Updates the value stored at the given index with a new value produced
    /// by a retag.
    fn retag(&mut self, cursor: Size, value: R);
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> RetagCx<'a, 'tcx, Bx, PlaceRef<'tcx, Bx::Value>>
    for PlaceRef<'tcx, Bx::Value>
{
    #[inline]
    fn phi(&mut self, _bx: &mut Bx, _branches: Vec<(Bx::BasicBlock, Self)>) {}

    #[inline]
    fn resolve(&self, _bx: &mut Bx) -> PlaceRef<'tcx, Bx::Value> {
        *self
    }

    #[inline]
    fn retag(&mut self, _cursor: Size, _value: PlaceRef<'tcx, Bx::Value>) {}
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> RetagCx<'a, 'tcx, Bx, OperandRef<'tcx, Bx::Value>>
    for OperandRefBuilder<'tcx, Bx::Value>
{
    fn phi(&mut self, bx: &mut Bx, branches: Vec<(Bx::BasicBlock, Self)>) {
        let operand_values = |val: OperandValue<Bx::Value>| -> Vec<Bx::Value> {
            match val {
                OperandValue::ZeroSized => vec![],
                OperandValue::Ref(_) => {
                    bug!("Unresolved reference to place within operand: {val:?}")
                }
                OperandValue::Immediate(v) => vec![v],
                OperandValue::Pair(a, b) => vec![a, b],
            }
        };

        // By creating a `RetagPlan` ahead-of-time, we can guarantee that this `phi` node
        // is not redundant. At least one branch retagged this value.
        let mut incoming_values = [vec![], vec![]];

        for (block, cursor) in branches.iter() {
            let op = cursor.build(bx.cx());
            for (idx, val) in operand_values(op.val).drain(..).enumerate() {
                incoming_values[idx].push((*block, val))
            }
        }

        for (idx, incoming) in incoming_values.iter_mut().enumerate() {
            if let Some((_, val)) = incoming.get(0) {
                let phi_val = bx.phi(bx.cx().val_ty(*val), incoming.drain(..));
                let offset = Size::from_bytes(idx);
                self.update_imm(offset, phi_val);
            }
        }
    }

    fn resolve(&self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value> {
        self.build(bx.cx())
    }

    fn retag(&mut self, cursor: Size, op: OperandRef<'tcx, Bx::Value>) {
        let (pointer, _) = op.val.pointer_parts();
        self.update_imm(cursor, pointer);
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx>
    for OperandRef<'tcx, Bx::Value>
{
    type Cx = OperandRefBuilder<'tcx, Bx::Value>;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self {
        let mut operand = self;
        operand.layout = operand.layout.for_variant(bx, idx);
        operand
    }

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self {
        self.extract_field(fx, bx, idx.as_usize())
    }

    #[inline]
    fn load_operand(self, _bx: &mut Bx) -> OperandRef<'tcx, Bx::Value> {
        self
    }

    #[inline]
    fn layout(&self) -> TyAndLayout<'tcx> {
        self.layout
    }

    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> OperandRef<'tcx, Bx::Value> {
        let OperandRef { layout, val, move_annotation } = *self;
        let (pointer, metadata) = val.pointer_parts();
        let retagged_val = bx.retag_reg(pointer, info);
        let retagged_val = if let Some(metadata) = metadata {
            OperandValue::Pair(retagged_val, metadata)
        } else {
            OperandValue::Immediate(retagged_val)
        };
        OperandRef { layout, val: retagged_val, move_annotation }
    }

    fn retag_cx(&self) -> OperandRefBuilder<'tcx, Bx::Value> {
        OperandRefBuilder::from_existing(*self)
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx> for PlaceRef<'tcx, Bx::Value> {
    type Cx = Self;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self {
        let mut place = self;
        place.layout = place.layout.for_variant(bx, idx);
        place
    }

    fn project_field(self, bx: &mut Bx, _fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self {
        self.project_field(bx, idx.as_usize())
    }

    fn load_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value> {
        bx.load_operand(self)
    }

    fn layout(&self) -> TyAndLayout<'tcx> {
        self.layout
    }

    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> PlaceRef<'tcx, Bx::Value> {
        bx.retag_mem(self.val.llval, info);
        *self
    }

    #[inline]
    fn retag_cx(&self) -> Self::Cx {
        *self
    }
}
