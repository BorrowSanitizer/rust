#![feature(rustc_private)]
#![warn(clippy::pedantic)]

extern crate rustc_driver;

use std::sync::Arc;

pub const BSAN_BUG_REPORT_URL: &str = "https://github.com/BorrowSanitizer/rust/issues/new";

pub const BSAN_DEFAULT_ARGS: &[&str] =
    &["--cfg=bsan", "-Zsanitizer=borrow", "-Zmir-emit-retag", "-Zmir-opt-level=0"];

pub struct BSanCallBacks {}
impl rustc_driver::Callbacks for BSanCallBacks {}

/// Execute a compiler with the given CLI arguments and callbacks.
pub fn run_compiler(
    mut args: Vec<String>,
    target_crate: bool,
    callbacks: &mut BSanCallBacks,
    using_internal_features: Arc<std::sync::atomic::AtomicBool>,
) -> ! {
    if target_crate {
        let additional_args = BSAN_DEFAULT_ARGS.iter().map(ToString::to_string).collect::<Vec<_>>();
        args.splice(1..1, additional_args);
    }
    let exit_code = rustc_driver::catch_with_exit_code(move || {
        rustc_driver::RunCompiler::new(&args, callbacks)
            .set_using_internal_features(using_internal_features)
            .run()
    });
    std::process::exit(exit_code)
}
