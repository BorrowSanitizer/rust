# <a href="https://borrowsanitizer.com"><img height="60px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href=""><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

This is our fork of the Rust compiler.

Nearly all of BorrowSanitizer can be implemented as an [external plugin](https://github.com/BorrowSanitizer/bsan). However, we still needed to modify the Rust compiler to support lowering [retag statements](https://doc.rust-lang.org/beta/nightly-rustc/rustc_middle/mir/enum.StatementKind.html#variant.Retag) from MIR into special LLVM intrinsics. The BorrowSanitizer plugin converts these intrinsics into calls to our runtime library. 

You can enable LLVM retag intrinsics with an unstable flag:
```
-Zllvm-emit-retag
```
You can specify whether to recurse into aggregate and sum types using another unstable flag:
```
-Zllvm-retag-fields[=<all|none|scalar>]
```
This has the same behavior as Miri's `-Zmiri-retag-fields`. It is set to `all` by default, and setting it to `none` is unsound. We do not support retagging dynamic trait objects yet. 

Our LLVM retag intrinsics (`@llvm.retag`) are defined in our [fork of LLVM](https://github.com/BorrowSanitizer/llvm-project). If you want to build the Rust compiler from source, then you will also need to build our fork of LLVM. Make sure to provide the following configuration in your [`bootstrap.toml`](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html#create-a-bootstraptoml) file.
```
[llvm]
download-ci-llvm = false
```
Visit Rust's [development guide](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html) for additional instructions on how to build the compiler from source.

Alternatively, you can use our [Docker image](https://github.com/BorrowSanitizer/rust/pkgs/container/rust). We use this image as the base for our dev container and release images.
