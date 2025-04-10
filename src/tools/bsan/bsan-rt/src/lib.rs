#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]
#![feature(strict_overflow_ops)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(alloc_layout_extra)]
#![feature(format_args_nl)]
#![allow(unused)]

extern crate alloc;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_ulonglong, c_void};
use core::mem::MaybeUninit;
use core::num::NonZero;
use core::ops::Deref;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::{fmt, mem, ptr};

mod global;
pub use global::*;
mod shadow;
use shadow::{ShadowHeap, table_indices};

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, c_ulonglong) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Print = unsafe extern "C" fn(*const c_char);
pub type Exit = unsafe extern "C" fn() -> !;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BsanHooks {
    alloc: BsanAllocHooks,
    mmap: MMap,
    munmap: MUnmap,
    print: Print,
    exit: Exit,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BsanAllocHooks {
    malloc: Malloc,
    free: Free,
}

unsafe impl Allocator for BsanAllocHooks {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unsafe {
            match layout.size() {
                0 => Ok(NonNull::slice_from_raw_parts(layout.dangling(), 0)),
                // SAFETY: `layout` is non-zero in size,
                size => unsafe {
                    let raw_ptr: *mut u8 = mem::transmute((self.malloc)(layout.size()));
                    let ptr = NonNull::new(raw_ptr).ok_or(AllocError)?;
                    Ok(NonNull::slice_from_raw_parts(ptr, size))
                },
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        (self.free)(mem::transmute(ptr.as_ptr()))
    }
}

/// Unique identifier for an allocation
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AllocId(usize);

impl AllocId {
    pub fn new(i: usize) -> Self {
        AllocId(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
    /// An invalid allocation
    pub const fn null() -> Self {
        AllocId(0)
    }

    /// Represents any valid allocation
    pub const fn wildcard() -> Self {
        AllocId(1)
    }

    /// A global or stack allocation, which cannot be manually freed
    pub const fn sticky() -> Self {
        AllocId(2)
    }

    pub const fn min() -> Self {
        AllocId(3)
    }
}

impl fmt::Debug for AllocId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() { write!(f, "a{}", self.0) } else { write!(f, "alloc{}", self.0) }
    }
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct BorTag(usize);

impl BorTag {
    pub const fn new(i: usize) -> Self {
        BorTag(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
}

impl fmt::Debug for BorTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.0)
    }
}

/// Unique identifier for a source location. Every update to the tree
/// is associated with a `Span`, which allows us to provide a detailed history
/// of the actions that lead to an aliasing violation.
pub type Span = usize;

/// Pointers have provenance (RFC #3559). In Tree Borrows, this includes an allocation ID
/// and a borrow tag. We also include a pointer to the "lock" location for the allocation,
/// which contains all other metadata used to detect undefined behavior.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Provenance {
    pub alloc_id: AllocId,
    pub bor_tag: BorTag,
    pub alloc_info: *mut c_void,
}

impl Default for Provenance {
    fn default() -> Self {
        Self::null()
    }
}

impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    pub const fn null() -> Self {
        Provenance {
            alloc_id: AllocId::null(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value, which permits
    /// any access.
    pub const fn wildcard() -> Self {
        Provenance {
            alloc_id: AllocId::wildcard(),
            bor_tag: BorTag::new(0),
            alloc_info: core::ptr::null_mut(),
        }
    }
}

/// Every allocation is associated with a "lock" object, which is an instance of `AllocInfo`.
/// Provenance is the "key" to this lock. To validate a memory access, we compare the allocation ID
/// of a pointer's provenance with the value stored in its corresponding `AllocInfo` object. If the values
/// do not match, then the access is invalid. If they do match, then we proceed to validate the access against
/// the tree for the allocation.
#[repr(C)]
struct AllocInfo {
    pub alloc_id: AllocId,
    pub base_addr: usize,
    pub size: usize,
    pub align: usize,
    pub tree: *mut c_void,
}

impl AllocInfo {
    /// When we deallocate an allocation, we need to invalidate its metadata.
    /// so that any uses-after-free are detectable.
    fn dealloc(&mut self) {
        self.alloc_id = AllocId::null();
        self.base_addr = 0;
        self.size = 0;
        self.align = 1;
        // FIXME: free the tree
    }
}

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[no_mangle]
unsafe extern "C" fn bsan_init(hooks: BsanHooks) {
    let ctx = init_global_ctx(&hooks);
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

/// Copies the provenance stored in the range `[src_addr, src_addr + access_size)` within the shadow heap
/// to the address `dst_addr`. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[no_mangle]
extern "C" fn bsan_shadow_copy(dst_addr: usize, src_addr: usize, access_size: usize) {}

/// Clears the provenance stored in the range `[dst_addr, dst_addr + access_size)` within the
/// shadow heap. This function will silently fail, so it should only be called in conjunction with
/// `bsan_read` and `bsan_write` or as part of an interceptor.
#[no_mangle]
extern "C" fn bsan_shadow_clear(addr: usize, access_size: usize) {}

/// Loads the provenance of a given address from shadow memory and stores
/// the result in the return pointer.
#[no_mangle]
unsafe extern "C" fn bsan_load_prov(prov: *mut Provenance, address: usize) {
    let result = global_ctx().shadow_heap().load_prov(address);
    *prov = result;
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[no_mangle]
unsafe extern "C" fn bsan_store_prov(provenance: *const Provenance, address: usize) {
    let heap = &(*global_ctx()).shadow_heap();
    heap.store_prov(provenance, address);
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