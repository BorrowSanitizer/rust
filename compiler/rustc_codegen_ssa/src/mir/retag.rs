use std::marker::PhantomData;

use rustc_abi::{BackendRepr, FieldIdx, FieldsShape, VariantIdx, Variants};
use rustc_hir::def_id::DefId;
use rustc_middle::mir::{Place, ProtectorKind, RetagKind};
use rustc_middle::ty::layout::{HasTyCtxt, TyAndLayout};
use rustc_middle::ty::{self};
use rustc_session::config::BsanRetagFields;
use tracing::trace;

use super::operand::OperandValue;
use super::place::PlaceValue;
use super::{BuilderMethods, FunctionCx, LocalRef};
use crate::common::IntPredicate;
use crate::mir::place::PlaceRef;
use crate::traits::{ConstCodegenMethods, LayoutTypeCodegenMethods, MiscCodegenMethods};

// When we retag a Place, we need to traverse through all of its fields
// and/or variants and emit retags for all of the sub-places that contain references,
// Boxes, and other types that require retagging. Calculating a sub-place requires cg-ing pointer offsets
// from the initial place and branching on variants. Not all sub-places need to be retagged, so we cannot
// compute them eagerly. Instead, when traversing a place, we store unevaluated subplaces as "modifiers"
// from an initial place. Once we find a subplace that needs to be retagged, we apply all current modifiers
// to the "base" place that we started with. We store the intermediate results from calculating all subplaces
// along the "path" to the subplace we're visiting, so that when we traverse back up the path, we don't need to
// repeat work. For example, if a variant of an enum contains N sub-places that need retagging,
// then we only want to have to branch that variant once, instead of N times for each sub-place.

/// Either a variant or a field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Modifier {
    Variant(VariantIdx),
    Field(FieldIdx),
}

impl Modifier {
    fn apply_to<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>>(
        self,
        bx: &mut Bx,
        place: &PlaceRef<'tcx, Bx::Value>,
    ) -> (PlaceRef<'tcx, Bx::Value>, Option<(Bx::BasicBlock, Bx::BasicBlock)>) {
        match self {
            Modifier::Variant(idx) => {
                let cx = bx.cx();
                let discrminant_ty = place.layout.ty.discriminant_ty(cx.tcx());
                let discrminant_for_variant = place
                    .layout
                    .ty
                    .discriminant_for_variant(cx.tcx(), idx)
                    .expect("Invalid variant.");

                let discriminant_backend_ty =
                    bx.immediate_backend_type(bx.layout_of(discrminant_ty));
                let discriminant_for_variant =
                    bx.const_uint_big(discriminant_backend_ty, discrminant_for_variant.val);

                let discriminant_actual = place.codegen_get_discr(bx, discrminant_ty);

                let is_variant = bx.append_sibling_block("variant");

                let is_not_variant = bx.append_sibling_block("cont");

                let cond =
                    bx.icmp(IntPredicate::IntEQ, discriminant_for_variant, discriminant_actual);

                bx.cond_br(cond, is_variant, is_not_variant);

                bx.switch_to_block(is_variant);
                (place.project_downcast(bx, idx), Some((is_variant, is_not_variant)))
            }
            Modifier::Field(field_idx) => (place.project_field(bx, field_idx.as_usize()), None),
        }
    }
}
struct RetagCx<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> {
    kind: RetagKind,
    places: Vec<PlaceRef<'tcx, Bx::Value>>,
    modifiers: Vec<Modifier>,
    branches: Vec<Bx::BasicBlock>,
    unique_did: Option<DefId>,
    data: PhantomData<&'a ()>,
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> RetagCx<'a, 'tcx, Bx> {
    fn visit(bx: &mut Bx, base: PlaceRef<'tcx, Bx::Value>, kind: RetagKind) {
        let unique_did =
            bx.cx().sess().unique_is_unique().then(|| bx.tcx().lang_items().ptr_unique()).flatten();
        let mut visitor = Self {
            kind,
            places: vec![base],
            modifiers: vec![],
            branches: vec![],
            unique_did,
            data: PhantomData::default(),
        };
        visitor.visit_value(bx, base.layout);
    }

    fn retag(&self, bx: &mut Bx, place: PlaceRef<'tcx, Bx::Value>) {
        let is_freeze = place.layout.ty.is_freeze(bx.tcx(), bx.typing_env());
        let is_unpin = place.layout.ty.is_unpin(bx.tcx(), bx.typing_env());
        bx.retag(
            place.val,
            place.layout.size,
            self.kind,
            ProtectorKind::StrongProtector,
            is_freeze,
            is_unpin,
        )
    }

    /// Applies each of the current modifiers to the base PlaceRef, cg-ing along the way.
    #[allow(dead_code)]
    fn crystallize(&mut self, bx: &mut Bx) -> PlaceRef<'tcx, Bx::Value> {
        let mut curr_subplace = *self.places.last().unwrap();

        let modifiers: Vec<Modifier> = self.modifiers.drain(..).collect();

        for modifier in modifiers {
            let (subplace, branch) = modifier.apply_to(bx, &curr_subplace);
            if let Some((then, otherwise)) = branch {
                bx.switch_to_block(then);
                self.branches.push(otherwise)
            }
            curr_subplace = subplace;
            self.places.push(curr_subplace);
        }

        return curr_subplace;
    }

    // Recursive actions, ready to be overloaded.
    /// Visits the given value, dispatching as appropriate to more specialized visitors.
    #[inline(always)]
    fn visit_value(&mut self, bx: &mut Bx, layout: TyAndLayout<'tcx>) {
        // If this place is smaller than a pointer, we know that it can't contain any
        // pointers we need to retag, so we can stop recursion early.
        // This optimization is crucial for ZSTs, because they can contain way more fields
        // than we can ever visit.
        if layout.is_sized() && layout.size < bx.tcx().data_layout.pointer_size {
            return;
        }

        // Check the type of this value to see what to do with it (retag, or recurse).
        match layout.ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            ty::Dynamic(_data, _, ty::Dyn) => {}
            ty::Dynamic(_data, _, ty::DynStar) => {}
            &ty::Ref(..) => {
                let place = self.crystallize(bx);
                self.retag(bx, place);
            }

            ty::RawPtr(_, _) => {
                // We definitely do *not* want to recurse into raw pointers -- wide raw
                // pointers have fields, and for dyn Trait pointees those can have reference
                // type!
                // We also do not want to reborrow them.
            }
            ty::Adt(adt, _) if adt.is_box() => {
                // Recurse for boxes, they require some tricky handling and will end up in `visit_box` above.
                // (Yes this means we technically also recursively retag the allocator itself
                // even if field retagging is not enabled. *shrug*)
                self.walk_value(bx, layout);
            }
            ty::Adt(adt, _) => {
                if self.unique_did == Some(adt.did()) {
                    let place = self.crystallize(bx);
                    let place = self.inner_ptr_of_unique(bx, place);
                    self.retag(bx, place);
                }
            }
            _ => {
                // Not a reference/pointer/box. Only recurse if configured appropriately.
                let recurse = match bx.cx().sess().retag_fields() {
                    BsanRetagFields::None => false,
                    BsanRetagFields::All => true,
                    BsanRetagFields::Scalar => {
                        // Matching `ArgAbi::new` at the time of writing, only fields of
                        // `Scalar` and `ScalarPair` ABI are considered.
                        matches!(
                            layout.backend_repr,
                            BackendRepr::Scalar(..) | BackendRepr::ScalarPair(..)
                        )
                    }
                };
                if recurse {
                    self.walk_value(bx, layout)
                }
            }
        }
    }

    /// Called each time we recurse down to a field of a "product-like" aggregate
    /// (structs, tuples, arrays and the like, but not enums), passing in old (outer)
    /// and new (inner) value.
    /// This gives the visitor the chance to track the stack of nested fields that
    /// we are descending through.
    #[inline(always)]
    fn visit_field(&mut self, bx: &mut Bx, layout: TyAndLayout<'tcx>, idx: FieldIdx) {
        self.modifiers.push(Modifier::Field(idx));
        self.visit_value(bx, layout.field(bx.cx(), idx.as_usize()));
        if self.modifiers.is_empty() {
            self.places.pop().expect("A place should have been evaluated.");
        } else {
            self.modifiers.pop().expect("An unevaluated modifier should be present.");
        }
    }
    /// Called when recursing into an enum variant.
    /// This gives the visitor the chance to track the stack of nested fields that
    /// we are descending through.
    #[inline(always)]
    fn visit_variant(&mut self, bx: &mut Bx, layout: TyAndLayout<'tcx>, vidx: VariantIdx) {
        self.modifiers.push(Modifier::Variant(vidx));
        self.visit_value(bx, layout.for_variant(bx.cx(), vidx));
        if self.modifiers.is_empty() {
            self.places.pop().expect("A place should have been resolved.");
            let otherwise = self.branches.pop().expect("A conditional should have been inserted.");
            bx.br(otherwise);
            bx.switch_to_block(otherwise);
        } else {
            self.modifiers.pop();
        }
    }

    fn inner_ptr_of_unique(
        &mut self,
        bx: &mut Bx,
        unique_ptr: PlaceRef<'tcx, Bx::Value>,
    ) -> PlaceRef<'tcx, Bx::Value> {
        // Unfortunately there is some type junk in the way here: `unique_ptr` is a `Unique`...
        // (which means another 2 fields, the second of which is a `PhantomData`)
        assert_eq!(unique_ptr.layout.fields.count(), 2);
        let phantom = unique_ptr.layout.field(bx.cx(), 1);
        assert!(
            phantom.ty.ty_adt_def().is_some_and(|adt| adt.is_phantom_data()),
            "2nd field of `Unique` should be PhantomData but is {:?}",
            phantom.ty,
        );
        let nonnull_ptr = unique_ptr.project_field(bx, 0);
        // ... that contains a `NonNull`... (gladly, only a single field here)
        assert_eq!(nonnull_ptr.layout.fields.count(), 1);
        // ... whose only field finally is a raw ptr
        nonnull_ptr.project_field(bx, 0)
    }

    /// Traversal logic; should not be overloaded.
    fn walk_value(&mut self, bx: &mut Bx, layout: TyAndLayout<'tcx>) {
        let ty = layout.ty;

        trace!("walk_value: type: {ty}");

        // Special treatment for special types, where the (static) layout is not sufficient.
        match *ty.kind() {
            // If it is a trait object, switch to the real type that was used to create it.
            // ty placement with length 0, so we enter the `Array` case below which
            // indirectly uses the metadata to determine the actual length.

            // However, `Box`... let's talk about `Box`.
            ty::Adt(def, ..) if def.is_box() => {
                // `Box` has two fields: the pointer we care about, and the allocator.
                assert_eq!(layout.fields.count(), 2, "`Box` must have exactly 2 fields");

                if ty.is_box_global(bx.tcx()) {
                    let current_place = self.crystallize(bx);
                    let unique_ptr = current_place.project_field(bx, 0);
                    let inner_ptr = self.inner_ptr_of_unique(bx, unique_ptr);
                    self.retag(bx, inner_ptr);
                }

                // The second `Box` field is the allocator, which we recursively check for validity
                // like in regular structs.
                self.visit_field(bx, layout, FieldIdx::from_usize(1));
            }

            // Non-normalized types should never show up here.
            ty::Param(..)
            | ty::Alias(..)
            | ty::Bound(..)
            | ty::Placeholder(..)
            | ty::Infer(..)
            | ty::Error(..) => {}

            // The rest is handled below.
            _ => {}
        };

        // Visit the fields of this value.
        match &layout.fields {
            FieldsShape::Primitive => {}
            FieldsShape::Arbitrary { memory_index, .. } => {
                for idx in memory_index.indices() {
                    self.visit_field(bx, layout, idx);
                }
            }
            FieldsShape::Array { .. } => {
                for idx in layout.fields.index_by_increasing_offset() {
                    self.visit_field(bx, layout, FieldIdx::from_usize(idx));
                }
            }
            _ => {}
        }

        match &layout.variants {
            // If this is a multi-variant layout, find the right variant and proceed
            // with *its* fields.
            Variants::Multiple { tag_field, variants, .. } => {
                self.modifiers.push(Modifier::Field(FieldIdx::from_usize(*tag_field)));
                for vidx in variants.indices().into_iter() {
                    self.visit_variant(bx, layout, vidx);
                }
            }
            // For single-variant layouts, we already did anything there is to do.
            Variants::Single { .. } => {}
        }
    }
}

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    pub(crate) fn codegen_retag(&mut self, bx: &mut Bx, place: &Place<'tcx>, kind: RetagKind) {
        self.resolve_place(bx, place).map(|place| RetagCx::visit(bx, place, kind));
    }

    fn resolve_place(
        &mut self,
        bx: &mut Bx,
        place: &Place<'tcx>,
    ) -> Option<PlaceRef<'tcx, Bx::Value>> {
        if let Some(index) = place.as_local() {
            match self.locals[index] {
                LocalRef::Place(cg_dest) => Some(cg_dest),
                LocalRef::UnsizedPlace(cg_indirect_dest) => Some(cg_indirect_dest),
                LocalRef::PendingOperand => None,
                LocalRef::Operand(op) => {
                    let mono_ty = self.monomorphized_place_ty(place.as_ref());
                    if mono_ty.is_any_ptr() {
                        let place_val = match op.val {
                            OperandValue::Ref(r) => Some(r),
                            OperandValue::Immediate(llval) => {
                                Some(PlaceValue::new_sized(llval, op.layout.align.abi))
                            }
                            OperandValue::Pair(llptr, _) => {
                                Some(PlaceValue::new_sized(llptr, op.layout.align.abi).into())
                            }
                            OperandValue::ZeroSized => None,
                        };
                        place_val.map(|place_val| PlaceRef::new_sized(place_val.llval, op.layout))
                    } else {
                        None
                    }
                }
            }
        } else {
            Some(self.codegen_place(bx, place.as_ref()))
        }
    }
}
