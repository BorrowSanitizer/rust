use std::path::PathBuf;

use crate::core::build_steps::llvm::{LdFlags, configure_cmake};
use crate::core::build_steps::tool::{SourceType, prepare_tool_cargo};
use crate::core::build_steps::{compile, llvm};
use crate::core::builder::{Builder, RunConfig, ShouldRun, Step};
use crate::core::config::TargetSelection;
//use crate::utils::exec::command;
use crate::*;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BsanRT {
    pub compiler: Compiler,
    pub target: TargetSelection,
}

impl Step for BsanRT {
    type Output = PathBuf;
    fn should_run(run: ShouldRun<'_>) -> ShouldRun<'_> {
        run.alias("bsan-rt")
    }

    fn make_run(run: RunConfig<'_>) {
        run.builder.ensure(BsanRT {
            compiler: run.builder.compiler(run.builder.top_stage, run.builder.config.build),
            target: run.target,
        });
    }

    fn run(self, builder: &Builder<'_>) -> PathBuf {
        let compiler = self.compiler;
        let target = self.target;
        let mode = Mode::ToolRustc;
        let kind = Kind::Build;

        builder.ensure(compile::Rustc::new(compiler, target));

        let mut cargo = prepare_tool_cargo(
            builder,
            compiler,
            mode,
            target,
            kind,
            "src/tools/bsan/bsan-rt",
            SourceType::InTree,
            &Vec::new(),
        );

        cargo.rustflag("-Cpanic=abort");
        cargo.rustflag("-Cembed-bitcode=yes");
        cargo.rustflag("-Clto");
        cargo.env("BSAN_HEADER_DIR", builder.cargo_out(compiler, mode, target));
        let build_success = compile::stream_cargo(builder, cargo, vec![], &mut |_| {});
        if !build_success {
            crate::exit!(1);
        } else {
            let library = builder.cargo_out(compiler, mode, target).join("libbsan_rt.a");

            // Like other sanitizer runtimes, we want to install this runtime into
            // both rustlib and the root of the sysroot libdir
            let libdir = builder.sysroot_target_libdir(compiler, target);
            let rustc_libdir = builder.rustc_libdir(compiler);

            let dst = libdir.join("libbsan_rt.a");
            let rustc_dst = rustc_libdir.join("libbsan_rt.a");

            builder.copy_link(&library, &dst, FileType::NativeLibrary);
            builder.copy_link(&library, &rustc_dst, FileType::NativeLibrary);
            rustc_dst
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct BsanLLVMPass {
    pub compiler: Compiler,
    pub target: TargetSelection,
}

impl Step for BsanLLVMPass {
    type Output = PathBuf;
    fn should_run(run: ShouldRun<'_>) -> ShouldRun<'_> {
        run.alias("bsan-pass")
    }

    fn make_run(run: RunConfig<'_>) {
        run.builder.ensure(BsanLLVMPass {
            compiler: run.builder.compiler(run.builder.top_stage, run.builder.config.build),
            target: run.target,
        });
    }

    fn run(self, builder: &Builder<'_>) -> PathBuf {
        let target = self.target;
        let mode = Mode::ToolRustc;
        let llvm::LlvmResult { llvm_config, .. } = builder.ensure(llvm::Llvm { target });
        let out_dir = builder.cargo_out(self.compiler, mode, target);

        if builder.config.dry_run() {
            return out_dir.join("build");
        }

        let mut cfg = cmake::Config::new("src/tools/bsan/bsan-pass");
        cfg.define("LLVM_CONFIG", llvm_config);
        cfg.build_target("bsan_plugin");
        cfg.profile("Release");
        cfg.pic(true);
        cfg.out_dir(out_dir);
        configure_cmake(builder, target, &mut cfg, true, LdFlags::default(), &[]);
        let library = cfg.build().join("build").join("libbsan_plugin.so");

        let libdir = builder.sysroot_target_libdir(self.compiler, target);
        let rustc_libdir = builder.rustc_libdir(self.compiler);

        let dst = libdir.join("libbsan_plugin.so");
        let rustc_dst = rustc_libdir.join("libbsan_plugin.so");

        builder.copy_link(&library, &dst, FileType::NativeLibrary);
        builder.copy_link(&dst, &rustc_dst, FileType::NativeLibrary);
        library
    }
}
