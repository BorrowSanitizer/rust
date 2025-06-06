# <a href="https://borrowsanitizer.com"><img height="60px" src="https://borrowsanitizer.com/images/bsan.svg" alt="BorrowSanitizer" /></a> <a href="https://github.com/verus-lang/verus"><picture><source media="(prefers-color-scheme: dark)" height="60px" height="60px" srcset="https://borrowsanitizer.com/images/bsan-text-dark.svg"/><img height="60px" height="60px" src="https://borrowsanitizer.com/images/bsan-text-light.svg" alt="BorrowSanitizer" /></picture></a>

This is our fork of the Rust compiler. 

Nearly all of the components of BorrowSanitizer can be implemented as an [external plugin](https://github.com/BorrowSanitizer/bsan). However, we still needed to modify the Rustcompiler to support lowering [retag statements]() from MIR into special LLVM intrinsics, which our plugin converts into calls to our runtime library. With our cutom compiler, you can enable LLVM retag intrinsics using the following unstable flag:
```
-Zllvm-emit-retag
```
Our LLVM retag intrinsics (`@llvm.retag`) are defined in our [fork of LLVM](https://github.com/BorrowSanitizer/llvm-project). 

To build our compiler, you will need to build LLVM from source by providing the following configuration in [`bootstrap.toml`](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html#create-a-bootstraptoml).
```
[llvm]
download-ci-llvm = false
```
Visit the [development guide](https://rustc-dev-guide.rust-lang.org/building/how-to-build-and-run.html) for additional instructions on how to build the compiler from source.