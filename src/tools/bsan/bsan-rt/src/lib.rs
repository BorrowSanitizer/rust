#![cfg_attr(not(test), no_std)]
#![feature(allocator_api)]
#![feature(sync_unsafe_cell)]
#![feature(alloc_layout_extra)]
#![feature(strict_overflow_ops)]
#![allow(unused)]

extern crate alloc;

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::num::NonZero;
use core::ops::Deref;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr;
use core::ptr::null;

mod global;
use global::{global_ctx, init_global_ctx};

mod bsan_alloc;
pub use bsan_alloc::BsanAllocator;
#[cfg(test)]
pub use bsan_alloc::TEST_ALLOC;
mod shadow;
use shadow::{Provenance as ShadowProvenance, ShadowHeap, table_indices};

type AllocID = usize;
type BorrowTag = usize;

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Provenance {
    lock_address: *mut c_void,
    alloc_id: AllocID,
    borrow_tag: BorrowTag,
}

impl Default for Provenance {
    fn default() -> Self {
        Self { lock_address: ptr::null_mut(), alloc_id: 0, borrow_tag: 0 }
    }
}

impl ShadowProvenance for Provenance {}

#[no_mangle]
unsafe extern "C" fn bsan_init(alloc: BsanAllocator) {
    init_global_ctx(alloc);
}

#[no_mangle]
unsafe extern "C" fn bsan_load_prov(address: usize) -> Provenance {
    let heap = &(*global_ctx()).shadow_heap;
    heap.load_prov(address)
}

#[no_mangle]
unsafe extern "C" fn bsan_store_prov(provenance: *const Provenance, address: usize) {
    let heap = &(*global_ctx()).shadow_heap;
    heap.store_prov(provenance, address);
}

#[no_mangle]
extern "C" fn bsan_expose_tag(ptr: *mut c_void) {}

#[no_mangle]
extern "C" fn bsan_retag(ptr: *mut c_void, retag_kind: u8, place_kind: u8) -> u64 {
    0
}

#[no_mangle]
extern "C" fn bsan_read(ptr: *mut c_void, access_size: u64) {}

#[no_mangle]
extern "C" fn bsan_write(ptr: *mut c_void, access_size: u64) {}

#[no_mangle]
extern "C" fn bsan_func_entry() {}

#[no_mangle]
extern "C" fn bsan_func_exit() {}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    loop {}
}
