//! Support for emitting retag intrinsics.
use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::RetagKind;
use rustc_middle::mir::interpret::Allocation;
use rustc_middle::ty::Mutability;
use rustc_middle::ty::data_structures::IndexMap;
use rustc_middle::ty::layout::HasTypingEnv;
use rustc_middle::{bug, ty};

use super::{BuilderMethods, FunctionCx};
use crate::RetagInfo;
use crate::mir::operand::{OperandRef, OperandRefBuilder, OperandValue};
use crate::mir::place::PlaceRef;
use crate::mir::{Ty, TyAndLayout};
use crate::traits::{BaseTypeCodegenMethods, CodegenMethods};

/// A description of the pointers within a type that need to be retagged.
#[derive(Debug)]
enum RetagPlan<V> {
    /// A retag should be emitted for a pointer.
    EmitRetag(RetagInfo<V>),
    /// Indicates that one or more fields or variants of this type
    /// contain pointers that need to be retagged.
    Recurse(IndexMap<FieldIdx, RetagPlan<V>>, IndexMap<VariantIdx, RetagPlan<V>>),
}

impl<V> RetagPlan<V> {
    /// A helper for creating a `RetagPlan` for a pointer that can be reached through
    /// a series of field projections.
    fn for_fields(mut field_indices: Vec<FieldIdx>, plan: RetagPlan<V>) -> Self {
        let mut base = plan;
        for idx in field_indices.drain(..) {
            let (mut fields, variants) = (IndexMap::default(), IndexMap::default());
            fields.insert(idx, base);
            base = RetagPlan::Recurse(fields, variants);
        }
        base
    }
}

impl<'a, 'tcx, V> RetagPlan<V> {
    fn emit_retag<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        pointee_layout: TyAndLayout<'tcx>,
        ptr_kind: Option<Mutability>,
        retag_kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        let pointee_ty = pointee_layout.ty;

        let pointee_is_unpin: bool = pointee_ty.is_unpin(bx.tcx(), bx.typing_env())
            && pointee_ty.is_unsafe_unpin(bx.tcx(), bx.typing_env());
        let is_protected = matches!(retag_kind, RetagKind::FnEntry);

        let is_box = ptr_kind.is_none();
        let is_mutable = is_box || matches!(ptr_kind, Some(Mutability::Mut));

        let size = pointee_layout.size;

        let pin_imprecise = bx.tcx().sess.opts.unstable_opts.codegen_retag_no_precise_pinning;
        let pin_ranges = UnsafePinnedRanges::collect_ranges(bx, pointee_layout, pin_imprecise);

        if matches!(ptr_kind, Some(Mutability::Mut) | None if !pointee_is_unpin) {
            if let Some(&[_, range_size]) = pin_ranges.first()
                && range_size == pointee_layout.size
            {
                // If everything is `UnsafePinned`, then skip retags.
                return None;
            }
        }

        let pin_layout = Self::alloc_ranges(bx, pin_ranges);

        let im_imprecise = bx.tcx().sess.opts.unstable_opts.codegen_retag_no_precise_interior_mut;
        let im_ranges = UnsafeCellRanges::collect_ranges(bx, pointee_layout, im_imprecise);
        let im_layout = Self::alloc_ranges(bx, im_ranges);

        Some(RetagPlan::EmitRetag(RetagInfo {
            size,
            im_layout,
            pin_layout,
            is_protected,
            pointee_is_unpin,
            is_mutable,
            is_box,
        }))
    }

    // Creates a pointer to a global static allocation containing adjacent pairs of `usize`.
    // Returns a null poitner if the list of ranges is empty.
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

        let const_alloc = Allocation::from_bytes(&bytes, align, Mutability::Not, ());
        let const_alloc = bx.tcx().mk_const_alloc(const_alloc);
        let alloc_id = bx.tcx().reserve_and_set_memory_alloc(const_alloc);

        let global_alloc = bx.tcx().global_alloc(alloc_id);
        let const_alloc = global_alloc.unwrap_memory();
        bx.cx().static_addr_of(const_alloc, None)
    }

    fn for_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        retag_kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recrsion early.
        // This optimization is crucial for ZSTs, because they can contain way more fields
        // than we can ever visit.
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
                Self::emit_retag(bx, pointee_layout, Some(mt), retag_kind)
            }
            &ty::RawPtr(_, _) => None,
            ty::Adt(adt, _) if adt.is_box() => Self::visit_box(bx, fx, layout, retag_kind),

            _ => Self::walk_value(bx, fx, layout, retag_kind),
        }
    }

    fn walk_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        let (fields, variants) = if let Some(def) = layout.ty.ty_adt_def()
            && def.is_unsafe_cell()
        {
            let field_layout = layout.field(bx.cx(), FieldIdx::ZERO.as_usize());
            let fields: Vec<(FieldIdx, RetagPlan<Bx::Value>)> =
                Self::for_value(bx, fx, field_layout, kind)
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
                    Self::for_value(bx, fx, field_layout, kind).map(|plan| (*idx, plan))
                })
                .collect();
            let variants: Vec<(VariantIdx, RetagPlan<Bx::Value>)> = match &layout.variants {
                Variants::Multiple { variants, .. } => variants
                    .indices()
                    .filter_map(|vidx| {
                        let variant_layout = layout.for_variant(bx.cx(), vidx);
                        Self::for_value(bx, fx, variant_layout, kind).map(|plan| (vidx, plan))
                    })
                    .collect(),
                Variants::Single { .. } | Variants::Empty => Vec::new(),
            };
            (fields, variants)
        };

        (!fields.is_empty() || !variants.is_empty()).then(|| {
            RetagPlan::Recurse(fields.into_iter().collect(), variants.into_iter().collect())
        })
    }

    fn visit_box<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");
        let mut fields = Vec::new();

        // Only retag the inner pointer of a `Box` if it came from the global allocator.
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

            // 0: `*mut T`
            let inner_ptr = nonnull_ptr.field(bx, FieldIdx::ZERO.into());

            let inner_ptr_ty = fx.monomorphize(inner_ptr.ty);
            let pointee_ty = inner_ptr_ty
                .builtin_deref(true)
                .expect("innermost pointer of `NonNull` should be dereferenceable.");
            let pointee_layout = bx.layout_of(pointee_ty);

            if let Some(plan) = Self::emit_retag(bx, pointee_layout, None, kind) {
                fields.push((
                    FieldIdx::ZERO,
                    RetagPlan::for_fields(vec![FieldIdx::ZERO, FieldIdx::ZERO], plan),
                ));
            }
        }

        // We always try to retag the second field (the allocator)
        let field_layout = layout.field(bx.cx(), FieldIdx::ONE.as_usize());

        if let Some(plan) = Self::for_value(bx, fx, field_layout, kind) {
            fields.push((FieldIdx::ONE, plan));
        }

        (!fields.is_empty())
            .then(|| RetagPlan::Recurse(fields.into_iter().collect(), IndexMap::default()))
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    pub(crate) fn codegen_retag_operand(
        &mut self,
        bx: &mut Bx,
        op: OperandRef<'tcx, Bx::Value>,
        kind: RetagKind,
    ) -> OperandRef<'tcx, Bx::Value> {
        if let OperandValue::Ref(place_ref) = op.val {
            let place_ref = place_ref.with_type(op.layout);
            self.codegen_retag_place(bx, place_ref, kind);
            op
        } else if let Some(plan) = RetagPlan::<Bx::Value>::for_value(bx, self, op.layout, kind) {
            self.retag(bx, plan, op)
        } else {
            op
        }
    }

    pub(crate) fn codegen_retag_place(
        &mut self,
        bx: &mut Bx,
        place_ref: PlaceRef<'tcx, Bx::Value>,
        kind: RetagKind,
    ) {
        if let Some(plan) = RetagPlan::<Bx::Value>::for_value(bx, self, place_ref.layout, kind) {
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
            RetagPlan::Recurse(fields, variants) => {
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

/// Collects the ranges within a type that are covered by `UnsafeUnpinned`.
struct UnsafePinnedRanges;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> PerByteTracking<'a, 'tcx, Bx> for UnsafePinnedRanges {
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        ty.is_unpin(bx.tcx(), bx.cx().typing_env())
    }

    fn contains(bx: &mut Bx, ty: Ty<'tcx>) -> bool {
        let tcx = bx.tcx();
        match ty.kind() {
            ty::Adt(adt, _) => Some(adt.did()) == tcx.lang_items().unsafe_pinned_type(),
            _ => false,
        }
    }
}

/// A visitor trait that collects the ranges within a type's layout that satisfy a given predicate.
trait PerByteTracking<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> {
    // The range containing this type should be excluded.
    fn excludes(bx: &mut Bx, ty: Ty<'tcx>) -> bool;
    // The range containing this type should be included.
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
            collector.extend(layout.size);
        }

        // We are always imprecise about sums and unions
        let is_union = matches!(layout.fields, FieldsShape::Union(..));
        let has_multiple_variants = matches!(layout.variants, Variants::Multiple { .. });

        if Self::contains(bx, layout.ty) || is_union || has_multiple_variants {
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

    fn collect_ranges(bx: &mut Bx, layout: TyAndLayout<'tcx>, imprecise: bool) -> Vec<[Size; 2]> {
        let mut collector = RangeCollector::default();
        Self::visit_layout(bx, &mut collector, layout, imprecise);
        collector.collect()
    }
}

/// Helper for collecting a list of ranges within the size of a type,
/// such that adjacent ranges are merged.
struct RangeCollector {
    /// The start of the current range
    cursor: Size,
    /// The size of the current range
    acc_offset: Size,
    /// A list of accumulated ranges (`[size, acc_offset]`).
    ranges: Vec<[Size; 2]>,
}

impl Default for RangeCollector {
    fn default() -> Self {
        Self { cursor: Size::ZERO, acc_offset: Size::ZERO, ranges: Vec::new() }
    }
}

impl RangeCollector {
    /// Extend the current range by `size` bytes
    fn extend(&mut self, size: Size) {
        self.acc_offset += size;
    }

    /// Move the collector forward by `size` bytes, recording the current
    /// range if this leaves a gap between the start of the last range and the
    /// current offset.
    fn advance(&mut self, offset: Size) {
        if offset == Size::ZERO {
            return;
        }

        if self.acc_offset > Size::ZERO {
            self.ranges.push([self.cursor, self.acc_offset]);
            self.cursor += self.acc_offset;
            self.acc_offset = Size::ZERO;
        }

        self.cursor += offset;
    }

    /// Consumes the collector, returning all recorded ranges.
    fn collect(mut self) -> Vec<[Size; 2]> {
        if self.acc_offset > Size::ZERO {
            self.ranges.push([self.cursor, self.acc_offset]);
        }
        self.ranges
    }
}

/// A value that can be retagged (either an operand or a place).
trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    // For operands, we use a context to track which values in the operand
    // are replaced by retags (e.g `%retag = __rust_retag_reg(%ptr, ..)`).
    // This is not necessary for places, which are updated "in-place"
    // (e.g. `__rust_retag_place(%ptr, ..)`) without creating a new alias.
    type Cx: RetagCx<'a, 'tcx, Bx, Self>;
    /// Creates a new context object that tracks updates to the current value.
    fn retag_cx(&self) -> Self::Cx;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn load_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    // Retags the current value, producing a new value.
    // For places, the new value is identical to the current one.
    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> Self;

    fn layout(&self) -> TyAndLayout<'tcx>;
}

/// Context used to collect updates to one or more values within an operand.
trait RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>>:
    Sized + Clone
{
    // Joins several contexts into a single operand, producing a phi node.
    fn phi(&mut self, bx: &mut Bx, branches: Vec<(Bx::BasicBlock, Self)>);

    /// Applies the updates that have been collected during traveral to the initial
    /// "base" value being retagged.
    fn resolve(&self, bx: &mut Bx) -> R;

    /// Updates the value stored at the given index with a new value produced
    /// by a retag.
    fn retag(&mut self, _cursor: Size, _value: R);
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

        let mut to_compare: [Option<Bx::Value>; 2] = [None, None];
        let mut found_different = [false, false];
        let mut components = [vec![], vec![]];

        for (block, cursor) in branches.iter() {
            let op = cursor.build(bx.cx());
            for (idx, val) in operand_values(op.val).drain(..).enumerate() {
                if let Some(prev) = to_compare[idx] {
                    found_different[idx] = prev != val;
                } else {
                    to_compare[idx] = Some(val);
                }
                components[idx].push((*block, val))
            }
        }

        for (idx, component) in components.iter_mut().enumerate() {
            if !component.is_empty() {
                if found_different[idx] {
                    let phi_val_ty = bx.cx().val_ty(to_compare[idx].unwrap());
                    let phi_val = bx.phi(phi_val_ty, component.drain(..));
                    let offset = Size::from_bytes(idx);
                    self.update_imm(offset, phi_val);
                }
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
