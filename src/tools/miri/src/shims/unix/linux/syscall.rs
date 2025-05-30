use rustc_abi::ExternAbi;
use rustc_span::Symbol;

use self::shims::unix::linux::eventfd::EvalContextExt as _;
use crate::helpers::check_min_arg_count;
use crate::shims::unix::linux::sync::futex;
use crate::*;

pub fn syscall<'tcx>(
    this: &mut MiriInterpCx<'tcx>,
    link_name: Symbol,
    abi: ExternAbi,
    args: &[OpTy<'tcx>],
    dest: &MPlaceTy<'tcx>,
) -> InterpResult<'tcx> {
    // We do not use `check_shim` here because `syscall` is variadic. The argument
    // count is checked bellow.
    this.check_abi_and_shim_symbol_clash(abi, ExternAbi::C { unwind: false }, link_name)?;
    // The syscall variadic function is legal to call with more arguments than needed,
    // extra arguments are simply ignored. The important check is that when we use an
    // argument, we have to also check all arguments *before* it to ensure that they
    // have the right type.

    let sys_getrandom = this.eval_libc("SYS_getrandom").to_target_usize(this)?;
    let sys_futex = this.eval_libc("SYS_futex").to_target_usize(this)?;
    let sys_eventfd2 = this.eval_libc("SYS_eventfd2").to_target_usize(this)?;

    let [op] = check_min_arg_count("syscall", args)?;
    match this.read_target_usize(op)? {
        // `libc::syscall(NR_GETRANDOM, buf.as_mut_ptr(), buf.len(), GRND_NONBLOCK)`
        // is called if a `HashMap` is created the regular way (e.g. HashMap<K, V>).
        num if num == sys_getrandom => {
            // Used by getrandom 0.1
            // The first argument is the syscall id, so skip over it.
            let [_, ptr, len, flags] = check_min_arg_count("syscall(SYS_getrandom, ...)", args)?;

            let ptr = this.read_pointer(ptr)?;
            let len = this.read_target_usize(len)?;
            // The only supported flags are GRND_RANDOM and GRND_NONBLOCK,
            // neither of which have any effect on our current PRNG.
            // See <https://github.com/rust-lang/rust/pull/79196> for a discussion of argument sizes.
            let _flags = this.read_scalar(flags)?.to_i32()?;

            this.gen_random(ptr, len)?;
            this.write_scalar(Scalar::from_target_usize(len, this), dest)?;
        }
        // `futex` is used by some synchronization primitives.
        num if num == sys_futex => {
            futex(this, args, dest)?;
        }
        num if num == sys_eventfd2 => {
            let [_, initval, flags] = check_min_arg_count("syscall(SYS_evetfd2, ...)", args)?;

            let result = this.eventfd(initval, flags)?;
            this.write_int(result.to_i32()?, dest)?;
        }
        num => {
            throw_unsup_format!("syscall: unsupported syscall number {num}");
        }
    };

    interp_ok(())
}
