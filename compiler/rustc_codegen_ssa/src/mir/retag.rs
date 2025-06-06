use bsan_shared::{Permission, ProtectorKind, RetagInfo};
use rustc_middle::mir::{Place, RetagKind};
use rustc_middle::ty::{self, Mutability};

use super::operand::OperandValue;
use super::place::PlaceValue;
use super::{BuilderMethods, FunctionCx, LocalRef};
use crate::mir::place::PlaceRef;

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    pub(crate) fn codegen_retag(&mut self, bx: &mut Bx, place: &Place<'tcx>, kind: RetagKind) {
        if let Some(place) = self.resolve_place(bx, place) {
            match place.layout.ty.kind() {
                ty::Adt(def, ..) if def.is_box() && place.layout.ty.is_box_global(bx.tcx()) => {
                    self.retag_unique_ty(bx, place, kind);
                }
                ty::Ref(_, _, mutability) => self.retag_ref_ty(bx, place, kind, *mutability),
                _ => {}
            }
        }
    }
    fn retag_ref_ty(
        &self,
        bx: &mut Bx,
        place: PlaceRef<'tcx, Bx::Value>,
        kind: RetagKind,
        mutability: Mutability,
    ) {
        let ty_is_freeze = place.layout.ty.is_freeze(bx.tcx(), bx.typing_env());
        let ty_is_unpin = place.layout.ty.is_unpin(bx.tcx(), bx.typing_env());
        let is_protected = kind == RetagKind::FnEntry;

        let perm_kind = match mutability {
            Mutability::Not if ty_is_unpin => Permission::new_reserved(ty_is_freeze, is_protected),
            Mutability::Mut if ty_is_freeze => Permission::new_frozen(),
            // Raw pointers never enter this function so they are not handled.
            // However raw pointers are not the only pointers that take the parent
            // tag, this also happens for `!Unpin` `&mut`s and interior mutable
            // `&`s, which are excluded above.
            _ => return,
        };

        let size = place.layout.size.bytes_usize();

        let protector_kind =
            if is_protected { ProtectorKind::StrongProtector } else { ProtectorKind::NoProtector };
        let perm = RetagInfo::new(size, perm_kind, protector_kind);
        bx.retag(place.val, perm);
    }

    /// Compute permission for `Box`-like type (`Box` always, and also `Unique` if enabled).
    /// These pointers allow deallocation so need a different kind of protector not handled
    /// by `from_ref_ty`.
    fn retag_unique_ty(&self, bx: &mut Bx, place: PlaceRef<'tcx, Bx::Value>, kind: RetagKind) {
        let ty = place.layout.ty;
        let ty_is_unpin = ty.is_unpin(bx.tcx(), bx.typing_env());
        if ty_is_unpin {
            let ty_is_freeze = ty.is_freeze(bx.tcx(), bx.typing_env());
            let is_protected = kind == RetagKind::FnEntry;
            let size = place.layout.size.bytes_usize();
            let protector_kind: ProtectorKind = if is_protected {
                ProtectorKind::WeakProtector
            } else {
                ProtectorKind::NoProtector
            };

            let perm_kind = Permission::new_reserved(ty_is_freeze, is_protected);
            let perm = RetagInfo::new(size, perm_kind, protector_kind);
            bx.retag(place.val, perm);
        }
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
                                Some(PlaceValue::new_sized(llptr, op.layout.align.abi))
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
