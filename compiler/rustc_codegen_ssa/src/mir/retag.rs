//! Support for emitting retags. Expands MIR `Retag` statements
//! to cover fields and variants.
//!
//! We emit retags for both operands and places. Each retagging mode has different semantics.
//! An *operand* retag creates a new value, or alias, for the pointer being retagged. This value
//! needs to be inserted into the operand to replace the old value. A *place* retag updates the
//! tag of the pointer in-place at the memory location where it's being stored. The method for this
//! will vary depending on how downstream tools manage tags, so unlike operands, we do not need to
//! make any changes to the place during codegen.
//!
#![allow(unused)]
use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, LayoutData, Size, VariantIdx, Variants};
use rustc_index::IndexVec;
use rustc_middle::mir::{Place, RetagKind, RetagParams};
use rustc_middle::ty::layout::TyAndLayout;
use rustc_middle::{bug, ty};
use rustc_target::spec::RetagFields;

use super::{BuilderMethods, FunctionCx};
use crate::mir::LocalRef;
use crate::mir::operand::{OperandRef, OperandValue};
use crate::mir::place::PlaceRef;
use crate::traits::{BaseTypeCodegenMethods, MiscCodegenMethods};

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    /// Emits a retag for a generic place. If the place is a local variable, then we retag its
    /// operand and overwrite the local. Likewise, if the operand is a reference to the place,
    /// the we apply a retag.
    pub(crate) fn codegen_retag(&mut self, bx: &mut Bx, place: &Place<'tcx>, kind: RetagKind) {
        if let Some(index) = place.as_local() {
            match self.locals[index] {
                LocalRef::PendingOperand => return,
                LocalRef::Operand(op) => {
                    if let OperandValue::Ref(place) = op.val {
                        RetagCx::retag(self, bx, place.with_type(op.layout), kind);
                    } else {
                        let retagged_operand = RetagCx::retag(self, bx, op, kind);
                        self.overwrite_local(index, LocalRef::Operand(retagged_operand));
                    }
                    return;
                }
                _ => {}
            }
        }
        let place = self.codegen_place(bx, place.as_ref());
        RetagCx::retag(self, bx, place, kind);
    }
}

/// A place or operand that can be retagged. This mostly abstracts over
/// the operation available for values that have an associated layout, but
/// it is also used to associated each type of value with a `ValueCx` that can
/// be used to perform updates during traversal. At the moment, this is only used
/// for operands.
trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    type Cx: ValueCx<'a, 'tcx, Bx, Self>;

    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn resolve_to_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    fn retag(
        &self,
        bx: &mut Bx,
        pointee_layout: TyAndLayout<'tcx>,
        perm: u64,
        fn_entry: bool,
    ) -> Self;

    fn layout(&self) -> TyAndLayout<'tcx>;

    /// Creates a new context for updating the current value.
    fn vcx(&self) -> Self::Cx;
}

/// Context used to collect updates to one or more values within an operand.
trait ValueCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>>:
    Sized + Clone
{
    /// Identifies a sub-value within the parent value.
    type ValueIdx: Sized + Copy;

    fn phi(bx: &mut Bx, branches: Vec<(Self, Bx::BasicBlock)>) -> Self;

    /// Applies the updates that have been collected during traveral to the initial
    /// "base" value being retagged.
    fn resolve(&self, base: R) -> R;

    /// Offsets a value index to point to the value stored at the given field.
    fn project_field(
        layout: TyAndLayout<'tcx>,
        idx: FieldIdx,
        cursor: Self::ValueIdx,
    ) -> Self::ValueIdx;

    /// Updates the value stored at the given index with a new value produced
    /// by a retag.
    fn retag(&mut self, _cursor: Self::ValueIdx, _value: R) {}

    /// The default index, which should correspond to the first value in the operand.
    fn default_index() -> Self::ValueIdx;
}

/// The context used to generate a single `Retag` MIR statement.
struct RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> {
    kind: RetagKind,
    /// Whether the value we are visiting is within an `UnsafeCell`. This is updated during
    /// traversal whenever we enter or exit this type.
    in_unsafe_cell: bool,
    /// A series of blocks, starting with the block where the original `Retag` statement was
    /// located. A new block is added when visiting a variant of an enum. During traversal,
    /// the last block in this list is the "current" one where instructions are being inserted.
    blocks: Vec<Bx::BasicBlock>,
    /// The block containing the original retag statement.
    base_block: Bx::BasicBlock,
    /// A series of field offsets and variant casts leading to the current place being retagged.
    /// These have yet to be emitted, and will only lead to codegen if we actually need to retag
    /// this place.
    modifiers: Vec<Modifier>,
    /// The initial value provided via the `PlaceRef` or `OperandRef`.
    base_value: R,
    /// Values computed by "concretizing" the modifiers from the base place.
    values: Vec<R>,
    /// Additional context related to the value being updated. This is only used for operands.
    value_ctx: R::Cx,
    /// When we branch on an enum, we wait to terminate the branches until the next time we need to
    /// emit a retag, or when we have finished retagging.
    pending_root: Option<ConditionalRoot<'a, 'tcx, Bx, R>>,
}

/// A basic block containing the instructions for retagging a variant of an enum.
struct ConditionalBranch<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> {
    /// The discriminant for the variant
    discr_val: u128,
    /// The basic block
    block: Bx::BasicBlock,
    /// ValueIdx
    value_ctx: R::Cx,
    pending: Option<ConditionalRoot<'a, 'tcx, Bx, R>>,
}

struct ConditionalRoot<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> {
    /// The discriminant for the enum being retagged
    discr_val: Bx::Value,
    default_index_ctx: R::Cx,
    /// The block we are branching from
    root_block: Bx::BasicBlock,
    /// Branches for retagging each variant.
    branches: Vec<ConditionalBranch<'a, 'tcx, Bx, R>>,
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>>
    ConditionalRoot<'a, 'tcx, Bx, R>
{
    fn resolve(mut self, bx: &mut Bx, terminator: Bx::BasicBlock) -> R::Cx {
        bx.switch_to_block(self.root_block);

        let mut discr_blocks: Vec<(u128, Bx::BasicBlock)> = Vec::new();

        let mut discr_cursors: Vec<(R::Cx, Bx::BasicBlock)> = Vec::new();
        discr_cursors.push((self.default_index_ctx, self.root_block));

        for branch in self.branches.drain(..) {
            let ConditionalBranch { discr_val, block, pending, value_ctx } = branch;
            if let Some(root) = pending {
                root.resolve(bx, terminator);
            } else {
                bx.switch_to_block(block);
                bx.br(terminator);
            };
            discr_blocks.push((discr_val, block));
            discr_cursors.push((value_ctx, block));
        }

        bx.switch_to_block(self.root_block);
        bx.switch(self.discr_val, terminator, discr_blocks.drain(..));

        bx.switch_to_block(terminator);
        R::Cx::phi(bx, discr_cursors)
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, PlaceRef<'tcx, Bx::Value>>
    for ()
{
    type ValueIdx = ();

    #[inline]
    fn phi(_bx: &mut Bx, _branches: Vec<(Self, Bx::BasicBlock)>) -> Self {}

    #[inline]
    fn resolve(&self, template: PlaceRef<'tcx, Bx::Value>) -> PlaceRef<'tcx, Bx::Value> {
        template
    }

    #[inline]
    fn project_field(
        _layout: TyAndLayout<'tcx>,
        _idx: FieldIdx,
        _cursor: Self::ValueIdx,
    ) -> Self::ValueIdx {
    }

    fn default_index() -> Self::ValueIdx {}

    fn retag(&mut self, _cursor: (), _value: PlaceRef<'tcx, Bx::Value>) {}
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> ValueCx<'a, 'tcx, Bx, OperandRef<'tcx, Bx::Value>>
    for OperandValueCx<Bx::Value>
{
    type ValueIdx = FieldIdx;
    fn phi(bx: &mut Bx, mut branches: Vec<(Self, Bx::BasicBlock)>) -> Self {
        let mut sentinel = [None, None];
        let mut found_different = [false, false];
        let mut components = [vec![], vec![]];

        for (cursor, block) in branches.drain(..) {
            for (idx, value) in cursor.updates.iter().enumerate() {
                if let Some(value) = value {
                    if sentinel[idx].is_none() {
                        sentinel[idx] = Some(*value);
                    }
                    components[idx].push((block, *value))
                }
                found_different[idx] |= sentinel[idx] != *value;
            }
        }

        let pair = components
            .iter_mut()
            .enumerate()
            .map(|(idx, components)| {
                if found_different[idx] {
                    Some(bx.phi(bx.cx().type_ptr(), components.drain(..)))
                } else {
                    sentinel[idx]
                }
            })
            .collect::<Vec<_>>();

        OperandValueCx { updates: [pair[0], pair[1]] }
    }

    fn resolve(&self, template: OperandRef<'tcx, Bx::Value>) -> OperandRef<'tcx, Bx::Value> {
        OperandRef { layout: template.layout, val: (*self).into() }
    }

    fn project_field(
        layout: TyAndLayout<'tcx>,
        idx: FieldIdx,
        cursor: Self::ValueIdx,
    ) -> Self::ValueIdx {
        if layout.fields.offset(idx.into()) > Size::ZERO { FieldIdx::ONE } else { cursor }
    }

    fn default_index() -> FieldIdx {
        FieldIdx::ZERO
    }

    fn retag(&mut self, cursor: FieldIdx, op: OperandRef<'tcx, Bx::Value>) {
        let (pointer, _) = op.val.pointer_parts();
        self.updates[cursor.index()] = Some(pointer);
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
        pointee_layout: TyAndLayout<'tcx>,
        perm: u64,
        fn_entry: bool,
    ) -> PlaceRef<'tcx, Bx::Value> {
        let pointer = self.val.llval;
        let size = pointee_layout.size;
        bx.retag_place(pointer, size, perm, fn_entry);
        *self
    }

    fn vcx(&self) -> Self::Cx {}
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
        pointee_layout: TyAndLayout<'tcx>,
        perm: u64,
        fn_entry: bool,
    ) -> OperandRef<'tcx, Bx::Value> {
        let OperandRef { layout, val } = self.resolve_to_operand(bx);
        let (pointer, metadata) = val.pointer_parts();
        let size = pointee_layout.size;
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

/// Calculating a sub-place requires emitting instructions to calculate pointer offsets and branch on variants.
/// Since not all sub-places need to be retagged, we want to avoid inserting these instructions until we know that they
/// are necessary. When traversing a place, we store unevaluated subplaces as "modifiers" from an initial place. Once we
/// find a subplace that needs to be retagged, we apply all current modifiers to the "base" place that we started with.
/// We store the intermediate subplaces along the "path" to the subplace that we're visiting, so that when we traverse
/// back up the path, we don't need to repeat work. A modifier is either a field of an aggregate or array type or a
/// variant of an enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Modifier {
    Variant(VariantIdx),
    Field(FieldIdx),
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> RetagCx<'a, 'tcx, Bx, R> {
    fn retag(fx: &mut FunctionCx<'a, 'tcx, Bx>, bx: &mut Bx, base_value: R, kind: RetagKind) -> R {
        let mut visitor = Self {
            blocks: vec![],
            base_block: bx.llbb(),
            modifiers: vec![],
            base_value,
            values: vec![],
            value_ctx: base_value.vcx(),
            pending_root: None,
            in_unsafe_cell: false,
            kind,
        };
        visitor.visit_value(fx, bx, base_value.layout(), R::Cx::default_index());
        let value_ctx = if let Some(root) = visitor.pending_root.take() {
            let terminator = bx.append_sibling_block("v_t");
            root.resolve(bx, terminator)
        } else {
            visitor.value_ctx
        };
        value_ctx.resolve(base_value)
    }

    fn visit_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recursion early.
        // This optimization is crucial for ZSTs, because they can contain way more fields
        // than we can ever visit.
        if layout.is_sized() && layout.size < bx.tcx().data_layout.pointer_size() {
            return;
        }
        // SIMD vectors may only contain raw pointers, integers, and floating point values,
        // which do not need to be retagged.
        if matches!(layout.backend_repr, BackendRepr::SimdVector { .. }) {
            return;
        }

        // Check the type of this value to see what to do with it (retag, or recurse).
        match layout.ty.kind() {
            &ty::Ref(_, pointee_ty, _) => {
                let pointee_ty = fx.monomorphize(pointee_ty);
                let pointee_layout = bx.layout_of(pointee_ty);
                if let Some(perm) = bx.tcx().retag_perm((
                    bx.typing_env(),
                    layout.ty,
                    pointee_ty,
                    RetagParams { kind: self.kind, in_unsafe_cell: self.in_unsafe_cell },
                )) {
                    let value = self.resolve_value(bx, fx, layout);
                    let retagged_value =
                        value.retag(bx, pointee_layout, perm, self.kind == RetagKind::FnEntry);
                    self.value_ctx.retag(cursor, retagged_value);
                }
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
            }
            _ => {}

            ty::Adt(adt, _) if adt.is_box() => {
                self.visit_box(fx, bx, layout, cursor);
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
                if recurse {
                    self.walk_value(fx, bx, layout, cursor);
                }
            }
        }
    }

    fn walk_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) {
        if let Some(def) = layout.ty.ty_adt_def()
            && def.is_unsafe_cell()
        {
            self.in_unsafe_cell = true;
            self.visit_field(fx, bx, layout, FieldIdx::from_usize(0), cursor);
            self.in_unsafe_cell = false;
            return;
        }

        // A type can have both fields and variants.
        match &layout.fields {
            FieldsShape::Union(_) => {}
            FieldsShape::Primitive => {}
            FieldsShape::Arbitrary { memory_index, .. } => {
                memory_index
                    .indices()
                    .for_each(|idx| self.visit_field(fx, bx, layout, idx, cursor));
            }
            FieldsShape::Array { .. } => {
                layout.fields.index_by_increasing_offset().for_each(|idx| {
                    self.visit_field(fx, bx, layout, FieldIdx::from_usize(idx), cursor)
                })
            }
        };
        match &layout.variants {
            Variants::Multiple { variants, .. } => {
                self.visit_variants(fx, bx, layout, &variants, cursor)
            }
            Variants::Single { .. } | Variants::Empty => {}
        }
    }

    fn visit_variant(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        idx: VariantIdx,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) -> Option<Bx::BasicBlock> {
        self.modifiers.push(Modifier::Variant(idx));
        let variant_layout = layout.for_variant(bx, idx);
        self.visit_value(fx, bx, variant_layout, cursor);
        if self.modifiers.is_empty() {
            self.values.pop().expect("A value should have been evaluated.");
            Some(self.blocks.pop().expect("A block should have been resolved."))
        } else {
            self.modifiers.pop();
            None
        }
    }

    fn visit_field(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        idx: FieldIdx,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) {
        let field_layout = layout.field(bx.cx(), idx.as_usize());
        let field_cursor = R::Cx::project_field(layout, idx, cursor);

        self.modifiers.push(Modifier::Field(idx));

        self.visit_value(fx, bx, field_layout, field_cursor);

        if self.modifiers.is_empty() {
            self.values.pop().expect("A value should have been evaluated.");
        } else {
            self.modifiers.pop().expect("An unevaluated modifier should be present.");
        }
    }

    fn visit_box(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) {
        assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");

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
                RetagParams { kind: self.kind, in_unsafe_cell: self.in_unsafe_cell },
            )) {
                let value = self.resolve_value(bx, fx, layout);
                let unique = value.project_field(bx, fx, FieldIdx::ZERO);
                let nonnull = unique.project_field(bx, fx, FieldIdx::ZERO);
                let inner = nonnull.project_field(bx, fx, FieldIdx::ZERO);
                let retagged_value =
                    inner.retag(bx, pointee_layout, perm, self.kind == RetagKind::FnEntry);
                self.value_ctx.retag(cursor, retagged_value);
            }
        }
        self.visit_field(fx, bx, layout, FieldIdx::ONE, cursor);
    }

    /// Creates a series of basic blocks for retagging each variant. If none of the variants
    /// need to be retagged, then no blocks are created and this function has no effect. If one or
    /// more variants need retagging, then all of these blocks are added as a pending `VariantBranch`.
    /// When recursion unwinds, the next time a retag needs to be emitted, a new block is created and
    /// all of the blocks in each pending `VariantBranch` instance are set to terminate on this one.
    fn visit_variants(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        layout: TyAndLayout<'tcx>,
        variants: &IndexVec<VariantIdx, LayoutData<FieldIdx, VariantIdx>>,
        cursor: <R::Cx as ValueCx<'a, 'tcx, Bx, R>>::ValueIdx,
    ) {
        // If some branches are already pending, then we want to be able to resolve them
        // to the point *before* we branch on the variants for this value (if we end up branching again).
        let previous_root = self.pending_root.take();
        let default_index_ctx = self.value_ctx.clone();

        // We create a block for each variant that needs to be retagged.
        let mut branches: Vec<ConditionalBranch<'a, 'tcx, Bx, R>> = vec![];

        for (vidx, _) in variants.indices().zip(&variants.raw) {
            if let Some(block) = self.visit_variant(fx, bx, layout, vidx, cursor) {
                // There are two possibilities for how we handle the block for a variant. If there are pending branches,
                // then this means that the last field in the variant's type was another sum type, so the block will end in
                // a switch statement. However, if there are no pending branches, then the last instruction in the block will
                // be a retag. At a later point, we will need to patch in a `br`.
                let pending = self.pending_root.take();

                let discr_val = layout
                    .ty
                    .discriminant_for_variant(bx.tcx(), vidx)
                    .expect("Invalid variant.")
                    .val;

                let value_ctx = self.value_ctx.clone();
                branches.push(ConditionalBranch { discr_val, block, pending, value_ctx });

                // We want to return to the block we started from.
                self.value_ctx = default_index_ctx.clone();
                let current_block = self.current_block();
                bx.switch_to_block(current_block);
            }
        }

        // Now we can replace the branches that were pending prior to this point. If we have new blocks to branch to,
        // then we want to resolve them before the switch. Otherwise, we'll carry them forward until the next
        // time that we need to insert an instruction.
        self.pending_root = previous_root;

        if !branches.is_empty() {
            let value = self.resolve_value(bx, fx, layout);
            let operand = value.resolve_to_operand(bx);
            let discr_ty = layout.ty.discriminant_ty(bx.tcx());
            let discr_val = operand.codegen_get_discr(fx, bx, discr_ty);

            self.pending_root = Some(ConditionalRoot {
                discr_val,
                default_index_ctx,
                root_block: self.current_block(),
                branches,
            });
        }
    }

    /// Computes the permission required for a retag and emits the intrinsic. Requires both the type of the place being
    /// retagged and the type of the pointee. If a `Box` is being retagged, then the `pointer_ty` is the outermost
    /// `Box`, even though it's the innermost pointer within the instance of `Unique` inside `Box` that actually receives
    /// the retag. We need this identify the place as being a `Box` when computing the permission. Otherwise, `pointer_ty`
    /// will be the type of the pointer or reference being retagged.

    fn current_block(&mut self) -> Bx::BasicBlock {
        self.blocks.last().copied().unwrap_or(self.base_block)
    }

    fn resolve_value(
        &mut self,
        bx: &mut Bx,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        layout: TyAndLayout<'tcx>,
    ) -> R {
        if let Some(root) = self.pending_root.take() {
            let terminator = bx.append_sibling_block("v_t");
            root.resolve(bx, terminator);
            bx.switch_to_block(terminator);
        }
        let mut current_value = self.values.last().copied().unwrap_or(self.base_value);
        for modifier in self.modifiers.drain(..) {
            match modifier {
                Modifier::Variant(idx) => {
                    let block = bx.append_sibling_block("v_t");
                    self.blocks.push(block);
                    bx.switch_to_block(block);
                    current_value = current_value.project_downcast(bx, idx);
                }
                Modifier::Field(idx) => {
                    current_value = current_value.project_field(bx, fx, idx);
                }
            }
            self.values.push(current_value);
        }
        assert_eq!(current_value.layout(), layout);
        current_value
    }
}
