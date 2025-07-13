//! Support for emitting retags. Expands MIR `Retag` statements
//! to cover fields and variants.
//!
//! We emit retags for both operands and places. Each retagging mode has different semantics.
//! An operand retag creates a new value, or alias, for the pointer being retagged. This value
//! needs to be inserted into the operand to replace the old value. A place retag updates the
//! tag of the pointer in-place at the memory location where it's being stored. The method for this
//! will vary depending on how downstream tools manage tags, so unlike operands, we do not need to
//! make any changes to the place during codegen.
//!
use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, Size, VariantIdx, Variants};
use rustc_middle::mir::{HasLocalDecls, Place, RetagKind, RetagParams};
use rustc_middle::ty::data_structures::IndexMap;
use rustc_middle::ty::layout::TyAndLayout;
use rustc_middle::{bug, ty};
use rustc_target::spec::RetagFields;

use super::{BuilderMethods, FunctionCx};
use crate::mir::LocalRef;
use crate::mir::operand::{OperandRef, OperandValue};
use crate::mir::place::PlaceRef;
use crate::traits::{BaseTypeCodegenMethods, ConstCodegenMethods, MiscCodegenMethods};

/// A description of the locations within a type that need retags.
#[derive(Debug)]
enum RetagPlan {
    /// Indicates that a retag should be emitted with the given
    /// size and permission type.
    EmitRetag(Size, u64),
    /// Indicates that one or more fields or variants of a type
    /// contain references that need to be retagged.
    Recurse(RetagLayout),
}

/// The set of fields and variants of a type that contain
/// references which need to be retagged.
#[derive(Debug, Default)]
struct RetagLayout {
    fields: IndexMap<FieldIdx, RetagPlan>,
    variants: IndexMap<VariantIdx, RetagPlan>,
}

impl RetagPlan {
    /// Creates a `RetagPlan` for a value that can be reached through
    /// a series of field projections.
    fn for_fields(mut field_indices: Vec<FieldIdx>, plan: RetagPlan) -> Self {
        let mut base = plan;
        for idx in field_indices.drain(..) {
            let mut branch = RetagLayout::default();
            branch.fields.insert(idx, base);
            base = RetagPlan::Recurse(branch);
        }
        base
    }
}

impl<'a, 'tcx> RetagPlan {
    fn for_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        kind: RetagKind,
        in_unsafe_cell: bool,
    ) -> Option<RetagPlan> {
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
            &ty::Ref(_, pointee_ty, _) => {
                let pointee_ty = fx.monomorphize(pointee_ty);
                let pointee_layout = bx.layout_of(pointee_ty);
                bx.tcx()
                    .retag_perm((
                        bx.typing_env(),
                        layout.ty,
                        pointee_ty,
                        RetagParams { kind, in_unsafe_cell },
                    ))
                    .map(|perm| RetagPlan::EmitRetag(pointee_layout.size, perm))
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
                None
            }

            ty::Adt(adt, _) if adt.is_box() => {
                Self::visit_box(bx, fx, layout, kind, in_unsafe_cell)
            }

            _ => {
                // Not a reference/pointer/box. Only recurse if configured appropriately.
                let recurse = match bx.cx().sess().opts.unstable_opts.mir_retag_fields {
                    RetagFields::None => false,
                    RetagFields::All => true,
                    RetagFields::Scalar => {
                        // Matching `ArgAbi::new` at the time of writing, only fields of
                        // `Scalar` and `ScalarPair` ABI are considered.
                        matches!(
                            layout.backend_repr,
                            BackendRepr::Scalar(..) | BackendRepr::ScalarPair(..)
                        )
                    }
                };
                if recurse { Self::walk_value(bx, fx, layout, kind, in_unsafe_cell) } else { None }
            }
        }
    }

    fn walk_value<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        kind: RetagKind,
        in_unsafe_cell: bool,
    ) -> Option<RetagPlan> {
        let (fields, variants) = if let Some(def) = layout.ty.ty_adt_def()
            && def.is_unsafe_cell()
        {
            let field_layout = layout.field(bx.cx(), FieldIdx::ZERO.as_usize());
            let fields: Vec<(FieldIdx, RetagPlan)> =
                Self::for_value(bx, fx, field_layout, kind, true)
                    .map(|plan| vec![(FieldIdx::ZERO, plan)])
                    .unwrap_or_default();
            (fields, Vec::new())
        } else {
            let indices: Vec<FieldIdx> = match &layout.fields {
                FieldsShape::Union(_) | FieldsShape::Primitive => Vec::new(),
                FieldsShape::Arbitrary { memory_index, .. } => memory_index.indices().collect(),
                FieldsShape::Array { .. } => {
                    layout.fields.index_by_increasing_offset().map(FieldIdx::from_usize).collect()
                }
            };

            let fields: Vec<(FieldIdx, RetagPlan)> = indices
                .iter()
                .filter_map(|idx| {
                    let field_layout = layout.field(bx.cx(), idx.as_usize());
                    Self::for_value(bx, fx, field_layout, kind, in_unsafe_cell)
                        .map(|plan| (*idx, plan))
                })
                .collect();

            let variants: Vec<(VariantIdx, RetagPlan)> = match &layout.variants {
                Variants::Multiple { variants, .. } => variants
                    .indices()
                    .filter_map(|vidx| {
                        let variant_layout = layout.for_variant(bx.cx(), vidx);
                        Self::for_value(bx, fx, variant_layout, kind, in_unsafe_cell)
                            .map(|plan| (vidx, plan))
                    })
                    .collect(),
                Variants::Single { .. } | Variants::Empty => Vec::new(),
            };
            (fields, variants)
        };

        (!fields.is_empty() || !variants.is_empty()).then(|| {
            RetagPlan::Recurse(RetagLayout {
                fields: fields.into_iter().collect(),
                variants: variants.into_iter().collect(),
            })
        })
    }

    fn visit_box<Bx: BuilderMethods<'a, 'tcx>>(
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
        kind: RetagKind,
        in_unsafe_cell: bool,
    ) -> Option<RetagPlan> {
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

            if let Some(perm) = bx.tcx().retag_perm((
                bx.typing_env(),
                layout.ty,
                pointee_ty,
                RetagParams { kind, in_unsafe_cell },
            )) {
                let leaf = RetagPlan::EmitRetag(pointee_layout.size, perm);
                fields.push((
                    FieldIdx::ZERO,
                    RetagPlan::for_fields(vec![FieldIdx::ZERO, FieldIdx::ZERO], leaf),
                ));
            }
        }

        let field_layout = layout.field(bx.cx(), FieldIdx::ONE.as_usize());

        if let Some(plan) = Self::for_value(bx, fx, field_layout, kind, in_unsafe_cell) {
            fields.push((FieldIdx::ONE, plan));
        }

        (!fields.is_empty()).then(|| {
            RetagPlan::Recurse(RetagLayout {
                fields: fields.into_iter().collect(),
                ..Default::default()
            })
        })
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    /// Emits a retag for a generic place. If the place is a local variable, then we retag its
    /// operand and overwrite the local. Likewise, if the operand is a reference to the place,
    /// the we apply a retag.
    pub(crate) fn codegen_retag(&mut self, bx: &mut Bx, place: &Place<'tcx>, kind: RetagKind) {
        let place_ty = place.ty(self.mir.local_decls(), bx.tcx());
        let mono_ty = self.monomorphize(place_ty.ty);
        let layout = bx.layout_of(mono_ty);
        if let Some(plan) = RetagPlan::for_value(bx, self, layout, kind, false) {
            if let Some(index) = place.as_local() {
                match self.locals[index] {
                    LocalRef::PendingOperand => return,
                    LocalRef::Operand(op) => {
                        if let OperandValue::Ref(place) = op.val {
                            let place = place.with_type(op.layout);
                            self.retag(bx, kind, plan, place);
                        } else {
                            let retagged_op = self.retag(bx, kind, plan, op);
                            self.overwrite_local(index, LocalRef::Operand(retagged_op));
                        }
                        return;
                    }
                    _ => {}
                }
            }
            let place = self.codegen_place(bx, place.as_ref());
            self.retag(bx, kind, plan, place);
        }
    }

    fn retag<R: Retagable<'a, 'tcx, Bx>>(
        &mut self,
        bx: &mut Bx,
        kind: RetagKind,
        plan: RetagPlan,
        value: R,
    ) -> R {
        let mut vcx = value.vcx();
        self.retag_inner(bx, &mut vcx, kind, &plan, value, Size::ZERO);
        vcx.resolve(value)
    }

    fn retag_inner<R: Retagable<'a, 'tcx, Bx>>(
        &mut self,
        bx: &mut Bx,
        vcx: &mut R::Cx,
        kind: RetagKind,
        plan: &RetagPlan,
        value: R,
        cursor: Size,
    ) {
        match plan {
            RetagPlan::EmitRetag(size, perm) => {
                let retagged_value = value.retag(bx, *size, *perm, kind == RetagKind::FnEntry);
                vcx.retag(cursor, retagged_value)
            }
            RetagPlan::Recurse(RetagLayout { fields, variants }) => {
                for (ix, plan) in fields.iter() {
                    let field_cursor = value.layout().fields.offset((*ix).as_usize()) + cursor;
                    let field_value = value.project_field(bx, self, *ix);
                    self.retag_inner(bx, vcx, kind, plan, field_value, field_cursor);
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
                            self.retag_inner(bx, vcx, kind, variant_plan, variant_value, cursor);
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

                        for (ix, plan) in variants.iter() {
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
                                kind,
                                plan,
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
}

/// A place or operand that can be retagged.
trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    type Cx: ValueCx<'a, 'tcx, Bx, Self>;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn resolve_to_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    fn retag(&self, bx: &mut Bx, size: Size, perm: u64, fn_entry: bool) -> Self;

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
    fn resolve(&self, base: R) -> R;

    /// Updates the value stored at the given index with a new value produced
    /// by a retag.
    fn retag(&mut self, _cursor: Size, _value: R);
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, PlaceRef<'tcx, Bx::Value>>
    for ()
{
    #[inline]
    fn phi(&mut self, _bx: &mut Bx, _branches: Vec<(Bx::BasicBlock, Self)>) {}

    #[inline]
    fn resolve(&self, template: PlaceRef<'tcx, Bx::Value>) -> PlaceRef<'tcx, Bx::Value> {
        template
    }

    fn retag(&mut self, _cursor: Size, _value: PlaceRef<'tcx, Bx::Value>) {}
}

#[derive(Debug, Copy, Clone)]
struct OperandValueCx<V: Copy> {
    updates: [Option<V>; 2],
}

impl<V: Copy> From<OperandValueCx<V>> for OperandValue<V> {
    fn from(value: OperandValueCx<V>) -> Self {
        match value.updates[..] {
            [Some(fst), Some(snd)] => OperandValue::Pair(fst, snd),
            [Some(val), None] => OperandValue::Immediate(val),
            [None, None] => OperandValue::ZeroSized,
            _ => bug!(),
        }
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, OperandRef<'tcx, Bx::Value>>
    for OperandValueCx<Bx::Value>
{
    fn phi(&mut self, bx: &mut Bx, branches: Vec<(Bx::BasicBlock, Self)>) {
        let mut components = [vec![], vec![]];
        for (block, cursor) in branches.iter() {
            for (idx, value) in cursor.updates.iter().enumerate() {
                if let Some(value) = value {
                    components[idx].push((*block, *value))
                }
            }
        }
        for (ix, component) in components.iter_mut().enumerate() {
            if !component.is_empty() {
                self.updates[ix] =
                    Some(bx.phi(bx.cx().val_ty(component[0].1), component.drain(..)));
            }
        }
    }

    fn resolve(&self, template: OperandRef<'tcx, Bx::Value>) -> OperandRef<'tcx, Bx::Value> {
        OperandRef { layout: template.layout, val: (*self).into() }
    }

    fn retag(&mut self, cursor: Size, op: OperandRef<'tcx, Bx::Value>) {
        let (pointer, _) = op.val.pointer_parts();
        let index = if cursor > Size::ZERO { 1 } else { 0 };
        assert!(self.updates[index].is_some());
        self.updates[index] = Some(pointer);
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx>
    for OperandRef<'tcx, Bx::Value>
{
    type Cx = OperandValueCx<Bx::Value>;

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

    fn retag(
        &self,
        bx: &mut Bx,
        size: Size,
        perm: u64,
        fn_entry: bool,
    ) -> OperandRef<'tcx, Bx::Value> {
        let OperandRef { layout, val } = self.resolve_to_operand(bx);
        let (pointer, metadata) = val.pointer_parts();
        let retagged_val = bx.retag_operand(pointer, size, perm, fn_entry);
        let retagged_val = if let Some(metadata) = metadata {
            OperandValue::Pair(retagged_val, metadata)
        } else {
            OperandValue::Immediate(retagged_val)
        };
        OperandRef { layout, val: retagged_val }
    }

    fn vcx(&self) -> OperandValueCx<Bx::Value> {
        let updates = match &self.val {
            OperandValue::Ref(_) => bug!(),
            OperandValue::Immediate(fst) => [Some(*fst), None],
            OperandValue::Pair(fst, snd) => [Some(*fst), Some(*snd)],
            OperandValue::ZeroSized => [None, None],
        };
        OperandValueCx { updates }
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx> for PlaceRef<'tcx, Bx::Value> {
    type Cx = ();

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

    fn retag(
        &self,
        bx: &mut Bx,
        size: Size,
        perm: u64,
        fn_entry: bool,
    ) -> PlaceRef<'tcx, Bx::Value> {
        let pointer = self.val.llval;
        bx.retag_place(pointer, size, perm, fn_entry);
        *self
    }

    fn vcx(&self) -> Self::Cx {}
}
