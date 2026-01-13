// Verifies that retag intrinsics show up as expected in LLVM IR with `-Zcodegen-emit-retag`.
//@ compile-flags: -Zcodegen-emit-retag -Copt-level=0

#![crate_type = "lib"]
#![feature(rustc_attrs)]
#![feature(allocator_api)]

use std::marker::PhantomPinned;
pub struct NotUnpin {
    _field: i32,
    _marker: PhantomPinned,
}

pub struct UnsafeInner {
    _field: std::cell::UnsafeCell<i16>,
}

// CHECK: @readonly_borrow(ptr align {{.*}} %0)
#[no_mangle]
pub fn readonly_borrow(_: &i32) {
    // CHECK:       start:
    // CHECK-NEXT:  call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @mutable_borrow(ptr align {{.*}} %0)
#[no_mangle]
pub fn mutable_borrow(_: &mut i32) {
    // CHECK:       start:
    // CHECK-NEXT:  call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @option_borrow(ptr align {{.*}} %0)
#[no_mangle]
pub fn option_borrow(_x: Option<&i32>) {
    // CHECK: start:
    // CHECK: br i1 %[[IS_NULL:.+]], label %[[V:.+]], label %[[V_T:.+]]
    // CHECK: [[V_T]]:
    // CHECK: phi ptr [ %0, %start ], [ %[[R:.+]], %[[V]] ]
    // CHECK: [[V]]:
    // CHECK-NEXT: %[[R]] = call ptr @__rust_retag_reg(ptr %0
    // CHECK: br label %[[V_T]]
}

// Retagging is a no-op for all `!Unpin`.
// CHECK: @readonly_notunpin_borrow(ptr align {{.*}} %0
#[no_mangle]
pub fn readonly_notunpin_borrow(_: &NotUnpin) {
    // CHECK:       start:
    // CHECK-NEXT:  call ptr @__rust_retag_reg(ptr %0
}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn mutable_notunpin_borrow(_: &mut NotUnpin) {}

enum E {
    A(&'static i8),
    B(&'static i32),
    C(&'static i64),
}

// CHECK: @multiple_variants(i64 %_x.0, ptr %0
#[no_mangle]
pub fn multiple_variants(_x: E) {
    // CHECK: start:
    // CHECK-NEXT: switch i64 %_x.0, label %[[V_T:.+]] [
    // CHECK-NEXT: i64 0, label %[[V0:.+]]
    // CHECK-NEXT: i64 1, label %[[V1:.+]]
    // CHECK-NEXT: i64 2, label %[[V2:.+]]
    // CHECK-NEXT: ]
    // CHECK: [[V_T]]:
    // CHECK-NEXT: phi ptr [ %0, %start ], [ %[[R0:.+]], %[[V0]] ], [ %[[R1:.+]], %[[V1]] ], [ %[[R2:.+]], %[[V2]] ]
    // CHECK: [[V0]]:
    // CHECK-NEXT: %[[R0]] = call ptr @__rust_retag_reg(ptr %0, i64 1
    // CHECK: [[V1]]:
    // CHECK-NEXT: %[[R1]] = call ptr @__rust_retag_reg(ptr %0, i64 4
    // CHECK: [[V2]]:
    // CHECK-NEXT: %[[R2]] = call ptr @__rust_retag_reg(ptr %0, i64 8
}

// CHECK: @_box(ptr align {{.*}} %0
#[no_mangle]
pub fn _box(x: Box<i32>) -> Box<i32> {
    // CHECK:       start:
    // CHECK-NEXT:  %[[R1:.+]] = call ptr @__rust_retag_reg(ptr %0
    // CHECK-NEXT:  %[[R2:.+]] = call ptr @__rust_retag_reg(ptr %[[R1]]
    // CHECK-NEXT:  ret ptr %[[R2]]
    x
}
// If a `Box` comes from the global allocator, then its innermost pointer
// should not be retagged, but we still want to retag the allocator.
// CHECK: @_box_custom(ptr align {{.*}} %x.0, ptr %0)
#[no_mangle]
pub fn _box_custom(x: Box<i32, &std::alloc::Global>) {
    // CHECK: start:
    // CHECK-NEXT: call ptr @__rust_retag_reg(ptr %0
    drop(x)
}

// CHECK: @slice(ptr %0
#[no_mangle]
pub fn slice(_: &[u8]) {
    // CHECK: start:
    // CHECK-NEXT: call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @mutable_slice(ptr %0
#[no_mangle]
pub fn mutable_slice(_: &mut [u8]) {
    // CHECK:       start:
    // CHECK-NEXT:  call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @unsafe_slice(ptr align {{.*}} %0
#[no_mangle]
pub fn unsafe_slice(_: &[UnsafeInner]) {
    // CHECK: start:
    // CHECK-NEXT: call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @str(ptr %0, i64 %_1.1)
#[no_mangle]
pub fn str(_: &[u8]) {
    // CHECK: start:
    // CHECK-NEXT: call ptr @__rust_retag_reg(ptr %0
}

// CHECK: @return_slice(ptr align {{.*}} %0, i64 %x.1)
#[no_mangle]
pub fn return_slice(x: &[u16]) -> &[u16] {
    // CHECK: start:
    // CHECK-NEXT: %[[R1:.+]] = call ptr @__rust_retag_reg(ptr %0
    // CHECK-NEXT: call ptr @__rust_retag_reg(ptr %[[R1]]
    x
}

// CHECK: @trait_borrow(ptr %0, ptr align {{.+}} %_1.1)
#[no_mangle]
pub fn trait_borrow(_: &dyn Drop) {
    // CHECK:       start:
    // CHECK-NEXT:  call ptr @__rust_retag_reg(ptr %0
}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn trait_mutable_borrow(_: &mut dyn Drop) {}

// CHECK: @option_trait_borrow(ptr %0, ptr %x.1)
#[no_mangle]
pub fn option_trait_borrow(x: Option<&dyn Drop>) {
    // CHECK: start:
    // CHECK: br i1 %[[IS_NULL:.+]], label %v, label %v_t
    // CHECK: v_t:
    // CHECK-NEXT: phi ptr [ %0, %start ], [ %[[R:.+]], %v ]
    // CHECK: v:
    // CHECK-NEXT: %[[R]] = call ptr @__rust_retag_reg(ptr %0
    // CHECK: br label %v_t
}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn option_trait_borrow_mut(_: Option<&mut dyn Drop>) {}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn trait_box(_: Box<dyn Drop + Unpin>) {}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn trait_mutref(_: &mut (dyn Drop + Unpin)) {}

// CHECK-NOT: @__rust_retag
#[no_mangle]
pub fn trait_option(x: Option<Box<dyn Drop + Unpin>>) -> Option<Box<dyn Drop + Unpin>> {
    x
}
