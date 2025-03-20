#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]
#![feature(strict_overflow_ops)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(alloc_layout_extra)]
#![feature(format_args_nl)]
#![allow(unused)]

extern crate alloc;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};
use core::mem::MaybeUninit;
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

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, i64) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Print = unsafe extern "C" fn(*const c_char);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BsanHooks {
    malloc: Malloc,
    free: Free,
    mmap: MMap,
    munmap: MUnmap,
    print: Print,
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

/// Unique identifier for a node within the tree
pub type BorTag = usize;

/// Unique identifier for a source location. Every update to the tree
/// is associated with a `Span`, which allows us to provide a detailed history
/// of the actions that lead to an aliasing violation.
pub type Span = usize;

/// Pointers have provenance (RFC #3559). In Tree Borrows, this includes an allocation ID
/// and a borrow tag. We also include a pointer to the "lock" location for the allocation,
/// which contains all other metadata used to detect undefined behavior.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Provenance {
    pub alloc_id: AllocID,
    pub bor_tag: BorTag,
    pub alloc_info: *mut c_void,
}

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    const fn null() -> Self {
        Provenance { alloc_id: 0, bor_tag: 0, alloc_info: core::ptr::null_mut() }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value, which permits
    /// any access. A provenance value with an `alloc_id` of zero and any non-zero `bor_tag`
    /// is treated as a wildcard provenance value.
    const fn wildcard() -> Self {
        Provenance { alloc_id: 0, bor_tag: 1, alloc_info: core::ptr::null_mut() }
    }
}

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[repr(C)]
struct AllocInfo {
    pub alloc_id: usize,
    pub base_addr: usize,
    pub size: usize,
    pub align: usize,
    pub tree: *mut c_void,
}

impl AllocInfo {
    /// When we deallocate an allocation, we need to invalidate its metadata.
    /// so that any uses-after-free are detectable.
    fn dealloc(&mut self) {
        self.alloc_id = 0;
        self.base_addr = 0;
        self.size = 0;
        self.align = 1;
        // FIXME: free the tree
    }
}

/// When a function returns, our instrumentation stores the provenance of its return value
/// in this thread-local array so that it can be read by the caller.
#[no_mangle]
#[thread_local]
#[allow(non_upper_case_globals)]
pub static mut __bsan_retval_tls: [Provenance; 100] = [Provenance::null(); 100];

/// When we call a function, we write the provenance of its arguments into this thread-local array
/// so that we can read them in the callee.
#[no_mangle]
#[thread_local]
#[allow(non_upper_case_globals)]
pub static mut __bsan_arg_tls: [Provenance; 100] = [Provenance::null(); 100];

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[no_mangle]
unsafe extern "C" fn bsan_init(hooks: BsanHooks) {
    let ctx = init_global_ctx(hooks);
    ui_test!(ctx, "bsan_init");
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[no_mangle]
unsafe extern "C" fn bsan_deinit() {
    ui_test!(global_ctx(), "bsan_deinit");
    deinit_global_ctx();
}

/// Creates a new borrow tag for the given provenance object.
#[no_mangle]
extern "C" fn bsan_retag(span: Span, prov: *mut Provenance, retag_kind: u8, place_kind: u8) {
    debug_assert!(prov != ptr::null_mut());
}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[no_mangle]
extern "C" fn bsan_read(span: Span, prov: *const Provenance, addr: usize, access_size: u64) {
    debug_assert!(prov != ptr::null_mut());
}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[no_mangle]
extern "C" fn bsan_write(span: Span, prov: *const Provenance, addr: usize, access_size: u64) {
    debug_assert!(prov != ptr::null_mut());
}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[no_mangle]
extern "C" fn bsan_load_prov(prov: *mut MaybeUninit<Provenance>, addr: usize) {
    debug_assert!(prov != ptr::null_mut());
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[no_mangle]
extern "C" fn bsan_store_prov(prov: *const Provenance, addr: usize) {
    debug_assert!(prov != ptr::null_mut());
}

/// Pushes a shadow stack frame
#[no_mangle]
extern "C" fn bsan_push_frame(span: Span) {}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[no_mangle]
extern "C" fn bsan_pop_frame(span: Span) {}

// Registers a heap allocation of size `size`
#[no_mangle]
extern "C" fn bsan_alloc(span: Span, prov: *mut MaybeUninit<Provenance>, addr: usize) {
    debug_assert!(prov != ptr::null_mut());

    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Registers a stack allocation of size `size`.
#[no_mangle]
extern "C" fn bsan_alloc_stack(span: Span, prov: *mut MaybeUninit<Provenance>, size: usize) {
    debug_assert!(prov != ptr::null_mut());
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Deregisters a heap allocation
#[no_mangle]
extern "C" fn bsan_dealloc(span: Span, prov: *mut Provenance) {
    debug_assert!(prov != ptr::null_mut());
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[no_mangle]
extern "C" fn bsan_expose_tag(prov: *const Provenance) {
    debug_assert!(prov != ptr::null_mut());
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    loop {}
}
