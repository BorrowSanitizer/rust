//! Support for emitting retags. Expands MIR `Retag` statements
//! to cover fields and variants.
//!
//! We emit retags for both operands and places. Each retagging mode has different semantics.
//! An operand retag creates a new value, or alias, for the pointer being retagged. This value
//! needs to be inserted into the operand to replace the old value. A place retag updates the
//! tag of the pointer in-place at the memory location where it's being stored. The method for this
//! will vary depending on how downstream tools manage tags, so unlike operands, we do not need to
//! make any changes to the place during codegen.

use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::interpret::{AllocId, Allocation};
use rustc_middle::mir::{Place, RetagKind};
use rustc_middle::ty::Mutability;
use rustc_middle::ty::data_structures::IndexMap;
use rustc_middle::ty::layout::{HasTyCtxt, HasTypingEnv};
use rustc_middle::{bug, ty};

use super::{BuilderMethods, FunctionCx};
use crate::RetagInfo;
use crate::mir::TyAndLayout;
use crate::mir::operand::{OperandRef, OperandRefBuilder, OperandValue};
use crate::mir::place::PlaceRef;
use crate::traits::{BaseTypeCodegenMethods, CodegenMethods};

pub(crate) fn place_needs_retag<'tcx>(place: &Place<'tcx>) -> bool {
    !place.is_indirect_first_projection()
}

/// A description of the locations within a type that need retags.
///
/// Each MIR-level `Retag` statement may correspond to one or more retags,
/// depending on the layout of the place being retagged. We recurse into each
/// field and variant to create a list of fields that are of `Box` or reference type,
/// along with the information required to perform a retag.
#[derive(Debug)]
enum RetagPlan<V> {
    /// Indicates that a retag should be emitted for a particular field.s
    EmitRetag(RetagInfo<V>),
    /// Indicates that one or more fields or variants of this type
    /// contain references that need to be retagged.
    Recurse(IndexMap<FieldIdx, RetagPlan<V>>, IndexMap<VariantIdx, RetagPlan<V>>),
}

impl<V> RetagPlan<V> {
    /// Creates a `RetagPlan` for a value that can be reached through
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
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        pointee_layout: TyAndLayout<'tcx>,
        ptr_kind: Option<Mutability>,
        retag_kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        let pointee_ty = pointee_layout.ty;
        let ty_is_unpin = pointee_ty.is_unpin(bx.tcx(), bx.typing_env());
        let ty_is_freeze = pointee_ty.is_freeze(bx.tcx(), bx.typing_env());
        let is_protected = matches!(retag_kind, RetagKind::FnEntry);
        if matches!(ptr_kind, Some(Mutability::Mut) | None if !ty_is_unpin) {
            // Mutable reference / Box to pinning type: retagging is a NOP.
            // FIXME: with `UnsafePinned`, this should do proper per-byte tracking.
            None
        } else {
            let im_layout = fx.im_span_alloc(pointee_layout);
            let size = pointee_layout.size;
            let im_layout = if let Some(alloc_id) = im_layout {
                let global_alloc = bx.tcx().global_alloc(alloc_id);
                let const_alloc = global_alloc.unwrap_memory();
                bx.cx().static_addr_of(const_alloc, Some("retag"))
            } else {
                bx.const_null(bx.type_ptr())
            };
            Some(RetagPlan::EmitRetag(RetagInfo {
                ptr_kind,
                size,
                ty_is_unpin,
                ty_is_freeze,
                is_protected,
                im_layout,
            }))
        }
    }
    fn for_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        retag_kind: RetagKind,
    ) -> Option<RetagPlan<Bx::Value>> {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recursion early.
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
                Self::emit_retag(bx, fx, pointee_layout, Some(mt), retag_kind)
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

        if layout.ty.is_box_global(bx.tcx()) {
            let unique = layout.field(bx, FieldIdx::ZERO.into());
            assert_eq!(unique.fields.count(), 2);

            let phantom = unique.field(bx, FieldIdx::ONE.into());
            assert!(
                phantom.ty.ty_adt_def().is_some_and(|adt| adt.is_phantom_data()),
                "2nd field of `Unique` should be PhantomData but is {:?}",
                phantom.ty,
            );

            let nonnull_ptr = unique.field(bx, FieldIdx::ZERO.into());
            assert_eq!(nonnull_ptr.fields.count(), 1);

            let inner_ptr = nonnull_ptr.field(bx, FieldIdx::ZERO.into());

            let inner_ptr_ty = fx.monomorphize(inner_ptr.ty);
            let pointee_ty = inner_ptr_ty
                .builtin_deref(true)
                .expect("innermost pointer of `NonNull` should be dereferenceable.");
            let pointee_layout = bx.layout_of(pointee_ty);

            if let Some(plan) = Self::emit_retag(bx, fx, pointee_layout, None, kind) {
                fields.push((
                    FieldIdx::ZERO,
                    RetagPlan::for_fields(vec![FieldIdx::ZERO, FieldIdx::ZERO], plan),
                ));
            }
        }

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
        let mut vcx = value.vcx();
        self.retag_inner(bx, &mut vcx, &plan, value, Size::ZERO);
        vcx.resolve(bx)
    }

    fn retag_inner<R: Retagable<'a, 'tcx, Bx>>(
        &mut self,
        bx: &mut Bx,
        vcx: &mut R::Cx,
        plan: &RetagPlan<Bx::Value>,
        value: R,
        cursor: Size,
    ) {
        match plan {
            RetagPlan::EmitRetag(info) => {
                let retagged_value = value.retag(bx, *info);
                vcx.retag(cursor, retagged_value)
            }
            RetagPlan::Recurse(fields, variants) => {
                for (ix, field_plan) in fields.iter() {
                    let field_cursor = value.layout().fields.offset((*ix).as_usize()) + cursor;
                    let field_value = value.project_field(bx, self, *ix);
                    self.retag_inner(bx, vcx, field_plan, field_value, field_cursor);
                }

                if !variants.is_empty() {
                    let operand = value.resolve_to_operand(bx);
                    let discr_ty = value.layout().ty.discriminant_ty(bx.tcx());
                    let discr_val = operand.codegen_get_discr(self, bx, discr_ty);

                    // If the discriminant is a constant, then we can just downcast and avoid branching.
                    if let Some(val) = bx.const_to_opt_u128(discr_val, false) {
                        let ix = VariantIdx::from_usize(val as usize);
                        let variant_value = value.project_downcast(bx, ix);
                        if let Some(variant_plan) = variants.get(&ix) {
                            self.retag_inner(bx, vcx, variant_plan, variant_value, cursor);
                        }
                    } else {
                        // Otherwise, we need a block for each variant.
                        let root_block = bx.llbb();
                        let mut variant_blocks: Vec<(u128, Bx::BasicBlock)> = vec![];

                        // Each "variant block" should arrive at the same terminator.
                        let terminator_block = bx.append_sibling_block("v_t");

                        // Each variant block may update the current value in different ways. We collect a value context
                        // alongside each block, and then merge these contexts in the terminator, producing one or more
                        // phi nodes for operands.
                        let mut updates: Vec<(Bx::BasicBlock, R::Cx)> =
                            vec![(root_block, (*vcx).clone())];

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
                            let mut variant_cx = (*vcx).clone();

                            self.retag_inner(
                                bx,
                                &mut variant_cx,
                                variant_plan,
                                variant_value,
                                cursor,
                            );
                            // If the variant contains another variant, then the current block at this point
                            // will be different than the one that we created above. We want this block to jump
                            // to the terminator block.
                            updates.push((bx.llbb(), variant_cx));
                            bx.br(terminator_block);

                            // However, regardless of where we ended up, we still need to record the new variant
                            // block we created so that we can switch to it from the root block.
                            variant_blocks.push((discr_val, variant_block))
                        }

                        bx.switch_to_block(root_block);
                        bx.switch(discr_val, terminator_block, variant_blocks.drain(..));
                        bx.switch_to_block(terminator_block);

                        vcx.phi(bx, updates);
                    }
                }
            }
        }
    }

    fn im_spans(&self, offset: Size, layout: TyAndLayout<'tcx>) -> Vec<[Size; 2]> {
        let tcx = self.cx.tcx();

        let is_freeze = layout.ty.is_freeze(tcx, self.cx.typing_env());

        if tcx.sess.opts.unstable_opts.codegen_retag_no_precise_interior_mut {
            if !is_freeze {
                return vec![[offset, layout.size]];
            } else {
                return vec![];
            }
        }

        let is_unsafe_cell = match layout.ty.kind() {
            ty::Adt(adt, _) => Some(adt.did()) == tcx.lang_items().unsafe_cell_type(),
            _ => false,
        };

        let is_union = matches!(layout.fields, FieldsShape::Union(..));

        let has_multiple_variants = matches!(layout.variants, Variants::Multiple { .. });

        if layout.ty.is_freeze(tcx, self.cx.typing_env()) {
            vec![]
        } else if is_unsafe_cell || is_union || has_multiple_variants {
            vec![[offset, layout.size]]
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
            indices
                .iter()
                .flat_map(|idx| {
                    let offset = offset + layout.fields.offset(idx.as_usize());
                    let field = layout.field(self.cx, idx.as_usize());
                    self.im_spans(offset, field)
                })
                .collect()
        }
    }

    fn im_span_alloc(&self, layout: TyAndLayout<'tcx>) -> Option<AllocId> {
        let tcx = self.cx.tcx();

        let im_spans = self.im_spans(Size::ZERO, layout);
        if im_spans.is_empty() {
            return None;
        }

        let bytes: Vec<u8> =
            im_spans.iter().flatten().flat_map(|u| u.bytes_usize().to_ne_bytes()).collect();
        let align = tcx.data_layout.ptr_sized_integer().align(&tcx.data_layout).abi;
        let alloc = Allocation::from_bytes(&bytes, align, Mutability::Not, ());

        let const_alloc = self.cx.tcx().mk_const_alloc(alloc);
        let alloc_id = self.cx.tcx().reserve_and_set_memory_alloc(const_alloc);
        Some(alloc_id)
    }
}

/// A place or operand that can be retagged.
trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    type Cx: ValueCx<'a, 'tcx, Bx, Self>;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn resolve_to_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> Self;

    fn layout(&self) -> TyAndLayout<'tcx>;

    /// Creates a new context for updating the current value.
    fn vcx(&self) -> Self::Cx;
}

/// Context used to collect updates to one or more values within an operand.
trait ValueCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>>:
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

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, PlaceRef<'tcx, Bx::Value>>
    for PlaceRef<'tcx, Bx::Value>
{
    #[inline]
    fn phi(&mut self, _bx: &mut Bx, _branches: Vec<(Bx::BasicBlock, Self)>) {}

    #[inline]
    fn resolve(&self, _bx: &mut Bx) -> PlaceRef<'tcx, Bx::Value> {
        *self
    }

    fn retag(&mut self, _cursor: Size, _value: PlaceRef<'tcx, Bx::Value>) {}
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, OperandRef<'tcx, Bx::Value>>
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

    #[inline]
    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self {
        let mut operand = self;
        operand.layout = operand.layout.for_variant(bx, idx);
        operand
    }

    #[inline]
    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self {
        self.extract_field(fx, bx, idx.as_usize())
    }

    #[inline]
    fn resolve_to_operand(self, _bx: &mut Bx) -> OperandRef<'tcx, Bx::Value> {
        self
    }

    #[inline]
    fn layout(&self) -> TyAndLayout<'tcx> {
        self.layout
    }

    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> OperandRef<'tcx, Bx::Value> {
        let OperandRef { layout, val, move_annotation } = self.resolve_to_operand(bx);
        let (pointer, metadata) = val.pointer_parts();
        let retagged_val = bx.retag_reg(pointer, info);
        let retagged_val = if let Some(metadata) = metadata {
            OperandValue::Pair(retagged_val, metadata)
        } else {
            OperandValue::Immediate(retagged_val)
        };
        OperandRef { layout, val: retagged_val, move_annotation }
    }

    #[inline]
    fn vcx(&self) -> OperandRefBuilder<'tcx, Bx::Value> {
        OperandRefBuilder::from_existing(*self)
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx> for PlaceRef<'tcx, Bx::Value> {
    type Cx = Self;

    #[inline]
    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self {
        let mut place = self;
        place.layout = place.layout.for_variant(bx, idx);
        place
    }

    #[inline]
    fn project_field(self, bx: &mut Bx, _fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self {
        self.project_field(bx, idx.as_usize())
    }

    #[inline]
    fn resolve_to_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value> {
        bx.load_operand(self)
    }

    #[inline]
    fn layout(&self) -> TyAndLayout<'tcx> {
        self.layout
    }

    #[inline]
    fn retag(&self, bx: &mut Bx, info: RetagInfo<Bx::Value>) -> PlaceRef<'tcx, Bx::Value> {
        bx.retag_mem(self.val.llval, info);
        *self
    }

    #[inline]
    fn vcx(&self) -> Self::Cx {
        *self
    }
}
