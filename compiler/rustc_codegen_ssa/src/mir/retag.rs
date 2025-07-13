//! Support for emitting retags. Expands MIR `Retag` statements
//! to cover fields and variants. This implementation began as
//! an extension of the `ValueVisitor` trait from const_eval, which
//! Miri uses to apply the effect of a retag at run-time.
use std::marker::PhantomData;
use std::vec;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, LayoutData, VariantIdx, Variants};
use rustc_index::IndexVec;
use rustc_middle::mir::{Local, Place, RetagKind, RetagParams};
use rustc_middle::ty::layout::{HasTyCtxt, TyAndLayout};
use rustc_middle::ty::{self, Ty};
use rustc_target::spec::RetagFields;

use super::{BuilderMethods, FunctionCx};
use crate::mir::LocalRef;
use crate::mir::operand::OperandRef;
use crate::mir::place::PlaceRef;
use crate::traits::MiscCodegenMethods;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    pub(crate) fn codegen_tag_assignment(
        &mut self,
        bx: &mut Bx,
        op: OperandRef<'tcx, Bx::Value>,
        index: Option<Local>,
        retag_kind: Option<RetagKind>,
    ) {
        if bx.tcx().sess.opts.unstable_opts.codegen_emit_retag {
            if let Some(retag_kind) = retag_kind {
                let pointer = op.val.pointer_parts().0;
                // We use "0" to indicate the absence of an MIR alias for the destination place.
                // This corresponds to the return local, which is never directly retagged.
                let index = index.unwrap_or(Local::ZERO);
                RetagCx::<Bx, OperandRef<'tcx, Bx::Value>>::visit(
                    self, bx, retag_kind, index, op, true,
                );
                bx.consume_tag(pointer, index);
            }
            if let Some(index) = index {
                self.tagged_locals.insert(index);
                if op.layout.ty.is_raw_ptr() {
                    let pointer = op.val.pointer_parts().0;
                    bx.link_tag(pointer, index);
                }
            }
        }
    }

    pub(crate) fn codegen_tag_assignment_for_box(
        &mut self,
        bx: &mut Bx,
        box_ty: Ty<'tcx>,
        operand: OperandRef<'tcx, Bx::Value>,
        index: Option<Local>,
        kind: Option<RetagKind>,
    ) {
        if box_ty.is_box_global(bx.tcx()) {
            let index = index.unwrap_or(Local::ZERO);
            if let Some(kind) = kind {
                let pointee_ty = box_ty.boxed_ty().expect("Expected this to be a `Box`");
                let pointee_layout = bx.layout_of(pointee_ty);
                let params = RetagParams { kind, in_unsafe_cell: false };
                if let Some(perm) =
                    bx.tcx().retag_perm((bx.typing_env(), box_ty, pointee_layout.ty, params))
                {
                    self.tagged_locals.insert(index);
                    operand.retag(
                        bx,
                        pointee_layout,
                        index,
                        perm,
                        kind == RetagKind::FnEntry,
                        true,
                    );
                }
            }
        }
    }

    /// Emits a retag for a generic place. If the place is an operand local, then we can apply the retag
    /// directly to the operand. Otherwise, we need to retag the pointer stored within the place.
    pub(crate) fn codegen_retag(&mut self, bx: &mut Bx, place: &Place<'tcx>, kind: RetagKind) {
        if let Some(index) = place.as_local()
            && let LocalRef::Operand(op) = self.locals[index]
            && !place.as_ref().is_indirect_first_projection()
        // If the operand's first projection is a dereference, then we can remove this projection to
        // convert it into a place (handled by `codegen_place`). Otherwise, we need to treat it as an
        // operand
        {
            RetagCx::<Bx, OperandRef<'tcx, Bx::Value>>::visit(self, bx, kind, index, op, false);
        } else {
            let index = place.local;
            let place = self.codegen_place(bx, place.as_ref());
            RetagCx::<Bx, PlaceRef<'tcx, Bx::Value>>::visit(self, bx, kind, index, place, false);
        };
    }
}

/// Additional state necessary for locating pointers to retag and emitting
/// retags in a single pass.
struct RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> {
    /// A series of blocks, starting with the block where the original `Retag` statement was
    /// located. A new block is added when visiting a variant of an enum. During traversal,
    /// the last block in this list is the "current" one where instructions are being inserted.
    blocks: Vec<Bx::BasicBlock>,
    /// The block containing the original retag statement.
    base_block: Bx::BasicBlock,
    /// Branches that need to be terminated before inserting the next retag.
    pending_branches: Vec<VariantBranch<Bx::BasicBlock, Bx::Value>>,
    /// A series of field offsets and variant casts leading to the current place being retagged.
    /// These have yet to be emitted, and will only lead to codegen if we actually need to retag
    /// this place.
    modifiers: Vec<Modifier>,
    /// The local variable that should be associated with the result of this retag.
    index: Local,
    /// The initial value provided via the `PlaceRef` or `OperandRef`.
    base_value: R,
    /// Values computed by "concretizing" the modifiers from the base place.
    values: Vec<R>,
    /// Whether to emit a `consume_tag` intrinsic immediately after the retag.
    consume: bool,
    data: PhantomData<(&'a (), &'tcx ())>,
}

/// A place or operand that receives a retag.
pub(crate) trait Retagable<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>: Copy {
    fn project_downcast(self, bx: &mut Bx, idx: VariantIdx) -> Self;

    fn project_field(self, bx: &mut Bx, fx: &mut FunctionCx<'a, 'tcx, Bx>, idx: FieldIdx) -> Self;

    fn resolve_to_operand(self, bx: &mut Bx) -> OperandRef<'tcx, Bx::Value>;

    fn retag(
        &self,
        bx: &mut Bx,
        pointee_layout: TyAndLayout<'tcx>,
        index: Local,
        perm: u64,
        fn_entry: bool,
        consume: bool,
    );

    fn layout(&self) -> TyAndLayout<'tcx>;
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx> for PlaceRef<'tcx, Bx::Value> {
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
        _index: Local,
        perm: u64,
        fn_entry: bool,
        _consume: bool,
    ) {
        let operand = self.resolve_to_operand(bx);
        let pointer = operand.val.pointer_parts().0;
        let size = pointee_layout.size;
        bx.retag_place(pointer, size, perm, fn_entry);
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> Retagable<'a, 'tcx, Bx>
    for OperandRef<'tcx, Bx::Value>
{
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
        index: Local,
        perm: u64,
        fn_entry: bool,
        consume: bool,
    ) {
        let operand = self.resolve_to_operand(bx);
        let pointer = operand.val.pointer_parts().0;
        let size = pointee_layout.size;
        bx.retag_operand(pointer, size, index, perm, fn_entry);
        if consume {
            bx.consume_tag(pointer, index);
        }
    }
}

/// Calculating a sub-place requires emitting instructions to calculate pointer offsets and branch on variants.
/// Since not all sub-places need to be retagged, we want to avoid inserting these instructions until we know that they are necessary. When traversing a place, we store unevaluated subplaces as
/// "modifiers" from an initial place. Once we find a subplace that needs to be retagged, we apply all current modifiers
/// to the "base" place that we started with. We store the intermediate subplaces along the "path" to the subplace
/// that we're visiting, so that when we traverse back up the path, we don't need to repeat work. A modifier is either
/// a field of an aggregate or array type or a variant of an enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Modifier {
    Variant(VariantIdx),
    Field(FieldIdx),
}

/// The data necessary for a yet-to-be-emitted `switch` instruction, which will
/// branch on the variants of an enum.
///
/// When we need to retag an enum, we have traverse through each of its variants to create
/// `BasicBlocks` for the ones that need to be retagged. Once we are done, we need to emit
/// a "terminator" block where each of the variant blocks end up. However, if we eagerly create
/// this terminator block immediately after visiting the variants, then it might not end up being
/// necessary, depending on where the enum is located within its parent type. For example, consider
/// retagging an instance of the struct `Outer`:
/// ```
/// struct Outer<'a, T> {
///     First(Inner<'a, T>)
///     Second(&'a T)
/// }
/// struct Inner<'a> {
///     First(&'a T)
///     Second(&'a T)
/// }
/// ```
/// When we branch on the variants of `Inner`, if we eagerly create a terminator block, then the
/// only purpose of this block will be to jump to the terminator block that we create for `Outer`.
/// We want to avoid creating this unnecessary intermediate block; instead, each of the branches of
/// `Inner` should immediately jump to the terminator block for `Outer`. To support this, once we
/// finish creating blocks for each variant, we store all of the data that we need to eventually
/// create and link up the terminator block within a `VariantBranch` struct.
struct VariantBranch<B, V> {
    /// The discriminant for the enum being retagged
    discr_val: V,
    /// The block we are branching from
    root_block: B,
    /// Blocks for retagging each variant.
    variant_blocks: Vec<VariantBlock<B>>,
}

/// A basic block containing the instructions for retagging a variant of an enum.
struct VariantBlock<B> {
    /// The discriminant for the variant
    discr_val: u128,
    /// The basic block
    block: B,
    /// If this block needs termination, then we still have to emit
    ///  a `br`. Otherwise, the block branched again, so we can defer to
    /// the other blocks downstream of it.
    needs_termination: bool,
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>, R: Retagable<'a, 'tcx, Bx>> RetagCx<'a, 'tcx, Bx, R> {
    fn visit(
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        kind: RetagKind,
        index: Local,
        base_value: R,
        consume: bool,
    ) {
        let mut visitor = Self {
            blocks: vec![],
            base_block: bx.llbb(),
            pending_branches: vec![],
            modifiers: vec![],
            index,
            base_value,
            values: vec![],
            data: PhantomData,
            consume,
        };
        visitor.visit_value(
            fx,
            bx,
            RetagParams { kind, in_unsafe_cell: false },
            base_value.layout(),
        );
        visitor.finalize_pending_branches(bx);
    }

    fn visit_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
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
                if let Some(perm) =
                    bx.tcx().retag_perm((bx.typing_env(), layout.ty, pointee_ty, params))
                {
                    let value = self.resolve_value(bx, fx, layout);
                    value.retag(
                        bx,
                        pointee_layout,
                        self.index,
                        perm,
                        params.kind == RetagKind::FnEntry,
                        self.consume,
                    );
                }
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
            }

            ty::Adt(adt, _) if adt.is_box() => {
                self.visit_box(fx, bx, params, layout);
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
                    self.walk_value(fx, bx, params, layout);
                }
            }
        }
    }

    fn walk_value(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
    ) {
        if let Some(def) = layout.ty.ty_adt_def()
            && def.is_unsafe_cell()
        {
            return self.visit_field(
                fx,
                bx,
                RetagParams { kind: params.kind, in_unsafe_cell: true },
                layout,
                FieldIdx::from_usize(0),
            );
        }

        // A type can have both fields and variants.
        match &layout.fields {
            FieldsShape::Union(_) => {}
            FieldsShape::Primitive => {}
            FieldsShape::Arbitrary { memory_index, .. } => {
                memory_index
                    .indices()
                    .for_each(|idx| self.visit_field(fx, bx, params, layout, idx));
            }
            FieldsShape::Array { .. } => {
                layout.fields.index_by_increasing_offset().for_each(|idx| {
                    self.visit_field(fx, bx, params, layout, FieldIdx::from_usize(idx))
                })
            }
        };

        match &layout.variants {
            Variants::Multiple { variants, .. } => {
                self.visit_variants(fx, bx, params, layout, &variants)
            }
            Variants::Single { .. } | Variants::Empty => {}
        }
    }

    fn visit_variant(
        &mut self,
        fx: &mut FunctionCx<'a, 'tcx, Bx>,
        bx: &mut Bx,
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
        idx: VariantIdx,
    ) -> Option<Bx::BasicBlock> {
        self.modifiers.push(Modifier::Variant(idx));
        let variant_layout = layout.for_variant(bx, idx);
        self.visit_value(fx, bx, params, variant_layout);
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
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
        idx: FieldIdx,
    ) {
        let field_layout = layout.field(bx.cx(), idx.as_usize());
        self.modifiers.push(Modifier::Field(idx));
        self.visit_value(fx, bx, params, field_layout);
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
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
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

            if let Some(perm) =
                bx.tcx().retag_perm((bx.typing_env(), layout.ty, pointee_ty, params))
            {
                let value = self.resolve_value(bx, fx, layout);
                let unique = value.project_field(bx, fx, FieldIdx::ZERO);
                let nonnull = unique.project_field(bx, fx, FieldIdx::ZERO);
                let inner = nonnull.project_field(bx, fx, FieldIdx::ZERO);
                inner.retag(
                    bx,
                    pointee_layout,
                    self.index,
                    perm,
                    params.kind == RetagKind::FnEntry,
                    self.consume,
                );
            }
        }
        self.visit_field(fx, bx, params, layout, FieldIdx::ONE);
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
        params: RetagParams,
        layout: TyAndLayout<'tcx>,
        variants: &IndexVec<VariantIdx, LayoutData<FieldIdx, VariantIdx>>,
    ) {
        // If some branches are already pending, then we want to be able to resolve them
        // to the point *before* we branch on the variants for this value (if we end up branching again).
        let mut pending_on_root: Vec<VariantBranch<Bx::BasicBlock, Bx::Value>> =
            self.pending_branches.drain(..).collect();

        // We also need to collect the new pending branches that we create by visiting each variant.
        // These branches will be resolved at some point in the future, *after* we finish visiting this value.
        let mut pending_from_root: Vec<VariantBranch<Bx::BasicBlock, Bx::Value>> = vec![];

        // We create a block for each variant that needs to be retagged.
        let mut variant_blocks: Vec<VariantBlock<Bx::BasicBlock>> = vec![];

        for (vidx, _) in variants.indices().zip(&variants.raw) {
            if let Some(block) = self.visit_variant(fx, bx, params, layout, vidx) {
                // There are two possibilities for how we handle the block for a variant. If there are pending branches,
                // then this means that the last field in the variant's type was another sum type, so the block will end in
                // a switch statement. However, if there are no pending branches, then the last instruction in the block will
                // be a retag. At a later point, we will need to patch in a `br`.
                let needs_termination = self.pending_branches.is_empty();

                // We need to drain the pending branches after visiting each variant. Otherwise, if two "adjacent" variants
                // need to be retagged, then the block for the first variant will end up jumping to the block for the second
                // variant.
                pending_from_root.append(&mut self.pending_branches.drain(..).collect());

                let discr_val = layout
                    .ty
                    .discriminant_for_variant(bx.cx().tcx(), vidx)
                    .expect("Invalid variant.")
                    .val;

                variant_blocks.push(VariantBlock { discr_val, block, needs_termination });

                // We want to return to the block we started from.
                let current_block = self.current_block();
                bx.switch_to_block(current_block);
            }
        }

        // Now we can replace the branches that were pending prior to this point. If we have new blocks to branch to,
        // then we want to resolve them before the switch. Otherwise, we'll carry them forward until the next
        // time that we need to insert an instruction.
        self.pending_branches.append(&mut pending_on_root);

        if !variant_blocks.is_empty() {
            let value = self.resolve_value(bx, fx, layout);
            let operand = value.resolve_to_operand(bx);
            let discr_ty = layout.ty.discriminant_ty(bx.cx().tcx());
            let discr_val = operand.codegen_get_discr(fx, bx, discr_ty);

            pending_from_root.push(VariantBranch {
                discr_val,
                root_block: self.current_block(),
                variant_blocks,
            });

            self.pending_branches.append(&mut pending_from_root)
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
        self.finalize_pending_branches(bx);
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

    // Consumes all of the pending `VariantBranch` instances to create a new terminating block where they all
    /// end up. As a side-effect, the current block is set to this this new one.
    fn finalize_pending_branches(&mut self, bx: &mut Bx) {
        if !self.pending_branches.is_empty() {
            let terminator_block = bx.append_sibling_block("v_t");
            for VariantBranch { discr_val, root_block, variant_blocks } in
                self.pending_branches.drain(..)
            {
                bx.switch_to_block(root_block);
                let mut variant_blocks: Vec<(u128, Bx::BasicBlock)> = variant_blocks
                    .iter()
                    .map(|VariantBlock { discr_val, block, needs_termination }| {
                        if *needs_termination {
                            bx.switch_to_block(*block);
                            bx.br(terminator_block);
                        }
                        (*discr_val, *block)
                    })
                    .collect();

                bx.switch_to_block(root_block);
                bx.switch(discr_val, terminator_block, variant_blocks.drain(..));
                bx.switch_to_block(terminator_block);
            }
            let last_block = self.blocks.last_mut().unwrap_or(&mut self.base_block);
            *last_block = terminator_block;
        }
    }
}
