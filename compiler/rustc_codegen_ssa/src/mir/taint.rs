use crate::mir::FunctionCx;
use crate::mir::operand::OperandValue;
use crate::mir::place::PlaceValue;
use crate::traits::{BaseTypeCodegenMethods, BuilderMethods};

impl<'a, 'tcx, Bx: BuilderMethods<'a, 'tcx>> FunctionCx<'a, 'tcx, Bx> {
    pub(crate) fn codegen_taint_operand(
        &mut self,
        bx: &mut Bx,
        operand_val: OperandValue<Bx::Value>,
    ) -> OperandValue<Bx::Value> {
        if bx.tcx().sess.opts.unstable_opts.codegen_emit_taint {
            let mut taint = |imm| -> Bx::Value {
                if bx.val_ty(imm) == bx.type_ptr() { bx.taint_reg(imm) } else { imm }
            };
            match operand_val {
                OperandValue::Ref(place_value) => {
                    self.codegen_taint_place(bx, place_value);
                    operand_val
                }
                OperandValue::Immediate(imm) => OperandValue::Immediate(taint(imm)),
                OperandValue::Pair(lhs, rhs) => OperandValue::Pair(taint(lhs), taint(rhs)),
                OperandValue::ZeroSized => operand_val,
            }
        } else {
            operand_val
        }
    }

    pub(crate) fn codegen_taint_place(&mut self, bx: &mut Bx, place_val: PlaceValue<Bx::Value>) {
        if bx.tcx().sess.opts.unstable_opts.codegen_emit_taint {
            let (ptr, _) = place_val.address().pointer_parts();
            bx.taint_mem(ptr)
        }
    }
}
