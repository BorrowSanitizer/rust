use core::ptr::null;
use crate::shadow::*;

type TestProv = u8;

impl Provenance for TestProv {}

#[test]
fn create_and_drop() {
    let _ = ShadowHeap::<TestProv>::default();
}

#[test]
fn load_null() {
    let s = ShadowHeap::<TestProv>::default();
    let k = unsafe { s.lookup(null()) };
}

#[test]
fn test_malloc_zero() {
    let mut s = ShadowHeap::<TestProv>::default();
    unsafe { s.malloc(null::<u8>() as *mut u8, 0) };
}

#[test]
fn test_malloc_small() {
    let mut s = ShadowHeap::<TestProv>::default();
    let ptr = Box::into_raw(Box::new(0u8)) as *mut u8;
    unsafe { s.malloc(ptr, 1) };
}

