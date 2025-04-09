#![cfg_attr(not(test), no_std)]
#![feature(sync_unsafe_cell)]
#![feature(strict_overflow_ops)]
#![feature(thread_local)]
#![feature(allocator_api)]
#![feature(alloc_layout_extra)]
#![feature(format_args_nl)]
#![allow(unused)]

extern crate alloc;
use alloc::boxed::Box;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_ulonglong, c_void};
use core::mem::MaybeUninit;
use core::num::NonZero;
#[cfg(not(test))]
use core::panic::PanicInfo;
use core::ptr::NonNull;
use core::{fmt, mem, ptr};

use block::Linkable;

mod global;

use global::*;

mod tree_borrows;
use log::debug;
use tree_borrows::tree_borrows_wrapper as TreeBorrows;

use crate::ui_test;

mod local;
pub use local::*;

mod block;
mod shadow;

// Atomic counter to assign unique IDs to each allocation
static ALLOC_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

union FreeListAddrUnion {
    free_list_next: *mut AllocMetadata,
    base_addr: *const c_void,
}

impl core::fmt::Debug for FreeListAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        unsafe { write!(f, "{:?}", self.base_addr) }
    }
}

/// This is the metadata stored with each allocation
#[derive(Debug)]
pub struct AllocMetadata {
    alloc_id: AllocId,
    base_addr: FreeListAddrUnion,
    tree_address: Box<TreeBorrows::Tree, BsanAllocHooks>,
}

unsafe impl Linkable<AllocMetadata> for AllocMetadata {
    fn next(&mut self) -> *mut *mut AllocMetadata {
        // we are re-using the space of base_addr to store the free list pointer
        // SAFETY: this is safe because both union fields are raw pointers
        unsafe { core::ptr::addr_of_mut!(self.base_addr.free_list_next) }
    }
}

impl AllocMetadata {
    fn base_addr(&self) -> *const c_void {
        // SAFETY: this is safe because both union fields are raw pointers
        unsafe { self.base_addr.base_addr }
    }

    fn dealloc(&mut self, borrow_tag: TreeBorrows::BorrowTag) {
        self.alloc_id = AllocId::invalid();
        self.tree_address.deallocate(self.base_addr(), borrow_tag);
        //TODO(obraunsdorf) free the allocation of the tree itself
    }
}

/// Pointers have provenance (RFC #3559). In Tree Borrows, this includes an allocation ID
/// and a borrow tag. We also include a pointer to the "lock" location for the allocation,
/// which contains all other metadata used to detect undefined behavior.

#[repr(C)]
struct Provenance {
    pub alloc_id: AllocId,
    pub borrow_tag: TreeBorrows::BorrowTag,
    pub lock_address: *const AllocMetadata,
}
impl Provenance {
    /// The default provenance value, which is assigned to dangling or invalid
    /// pointers.
    const fn null() -> Self {
        Provenance { alloc_id: AllocId::invalid(), borrow_tag: 0, lock_address: ptr::null() }
    }

    /// Pointers cast from integers receive a "wildcard" provenance value, which permits
    /// any access.
    const fn wildcard() -> Self {
        Provenance { alloc_id: AllocId::wildcard(), borrow_tag: 0, lock_address: ptr::null() }
    }
}

//#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, u64) -> *mut c_void;
//#[cfg(not(all(target_arch = "aarch64", target_os = "linux")))]
//pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, c_ulonglong) -> *mut c_void;
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
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllocId(usize);

impl AllocId {
    pub fn new(i: usize) -> Self {
        AllocId(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
    /// An invalid allocation
    pub const fn invalid() -> Self {
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

/// Unique identifier for a thread
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct ThreadId(usize);

impl ThreadId {
    pub fn new(i: usize) -> Self {
        ThreadId(i)
    }
    pub fn get(&self) -> usize {
        self.0
    }
}

/// Unique identifier for a node within the tree
#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

/// Initializes the global state of the runtime library.
/// The safety of this library is entirely dependent on this
/// function having been executed. We assume the global invariant that
/// no other API functions will be called prior to that point.
#[no_mangle]
unsafe extern "C" fn bsan_init(hooks: BsanHooks) {
    let ctx = init_global_ctx(hooks);
    let ctx = unsafe { &*ctx };
    init_local_ctx(ctx);
    ui_test!(ctx, "bsan_init");
}

/// Deinitializes the global state of the runtime library.
/// We assume the global invariant that no other API functions
/// will be called after this function has executed.
#[no_mangle]
unsafe extern "C" fn bsan_deinit() {
    let global_ctx = unsafe { &*global_ctx() };
    ui_test!(global_ctx, "bsan_deinit");
    deinit_local_ctx();
    deinit_global_ctx();
}

/// Creates a new borrow tag for the given provenance object.
#[no_mangle]
extern "C" fn bsan_retag(span: Span, prov: *mut Provenance, retag_kind: u8, place_kind: u8) {}

/// Records a read access of size `access_size` at the given address `addr` using the provenance `prov`.
#[no_mangle]
extern "C" fn bsan_read(span: Span, prov: *const Provenance, addr: usize, access_size: u64) {}

/// Records a write access of size `access_size` at the given address `addr` using the provenance `prov`.
#[no_mangle]
extern "C" fn bsan_write(span: Span, prov: *const Provenance, addr: usize, access_size: u64) {}

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
extern "C" fn bsan_load_prov(prov: *mut MaybeUninit<Provenance>, addr: usize) {
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Stores the given provenance value into shadow memory at the location for the given address.
#[no_mangle]
extern "C" fn bsan_store_prov(prov: *const Provenance, addr: usize) {}

/// Pushes a shadow stack frame
#[no_mangle]
extern "C" fn bsan_push_frame(span: Span) {}

/// Pops a shadow stack frame, deallocating all shadow allocations created by `bsan_alloc_stack`
#[no_mangle]
extern "C" fn bsan_pop_frame(span: Span) {}

/// Creates metadata for a heap allocation of the application.
/// (out:) `prov` is a pointer for returning the provenance (pointer metadata) for this allocation.
/// `span` is a ID to trace back to the source code location of the allocation
/// `object_address` is the address of the allocated object
/// `alloc_size` is the size of the allocated object
/// # Safety
///  The caller must ensure that `bsan_aalloc()` is only called after `bsan_init()` has
///  been called to initialize the global context, esp. the allocator and mmap hooks.

#[no_mangle]
unsafe extern "C" fn bsan_alloc(
    span: Span,
    prov: *mut MaybeUninit<Provenance>,
    object_address: *const c_void,
    alloc_size: usize,
) {
    debug_assert!(prov != ptr::null_mut());
    let ctx = &*global_ctx();
    let alloc_hooks = ctx.allocator();

    let tree = Box::new_in(TreeBorrows::Tree::new(object_address, alloc_size), alloc_hooks);
    let root_borrow_tag = tree.get_root_borrow_tag();
    let alloc_id = ctx.new_alloc_id();
    let mut lock_location = ctx.allocate_lock_location();
    let alloc_metadata = AllocMetadata {
        alloc_id,
        base_addr: FreeListAddrUnion { base_addr: object_address },
        tree_address: tree,
    };
    let lock_address = lock_location.as_mut().write(alloc_metadata) as *const AllocMetadata;
    (*prov).write(Provenance { alloc_id, borrow_tag: root_borrow_tag, lock_address });
}

/// Registers a stack allocation of size `size`.
#[no_mangle]
extern "C" fn bsan_alloc_stack(span: Span, prov: *mut MaybeUninit<Provenance>, size: usize) {
    unsafe {
        (*prov).write(Provenance::null());
    }
}

/// Deregisters a heap allocation
/// # Safety
/// Mutating alloc_metadata (i.e. deallocating the tree, and invalidating alloc_id) through the provencance
/// metadata (which is copy) is only thread-safe, if the application itself is thread-safe.
/// BSAN is not ensuring thread-safety here
/// if the
#[no_mangle]
unsafe extern "C" fn bsan_dealloc(span: Span, prov: *mut Provenance) {
    let prov = &mut *prov;
    let ctx = &*global_ctx();
    let alloc_metadata = &mut *(prov.lock_address as *mut AllocMetadata);
    if (alloc_metadata.alloc_id.get() != prov.alloc_id.get()) {
        panic!(
            "Allocation ID in pointer metadata ({}) does not match the one in the lock address ({})",
            prov.alloc_id.get(),
            alloc_metadata.alloc_id.get()
        );
    }
    alloc_metadata.dealloc(prov.borrow_tag);
}

/// Marks the borrow tag for `prov` as "exposed," allowing it to be resolved to
/// validate accesses through "wildcard" pointers.
#[no_mangle]
extern "C" fn bsan_expose_tag(prov: *const Provenance) {}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    loop {}
}

#[cfg(test)]
mod test {
    use core::alloc::{GlobalAlloc, Layout};
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    use super::*;
    use crate::global::test::TEST_HOOKS;

    #[test]
    fn bsan_malloc_alloc_id() {
        let bsan_test_hooks = TEST_HOOKS.clone();
        unsafe {
            bsan_init(bsan_test_hooks);
            let mut prov1 = MaybeUninit::<Provenance>::uninit();
            let span1 = 42;
            let prov1_ptr = (&mut prov1) as *mut _;
            bsan_alloc(span1, prov1_ptr, 0xaaaaaaaa as *const c_void, 10);
            let prov1 = prov1.assume_init();
            assert_eq!(prov1.alloc_id.get(), 3);
            let span2 = 43;
            let mut prov2 = MaybeUninit::<Provenance>::uninit();
            let prov2_ptr = (&mut prov2) as *mut _;
            bsan_alloc(span2, prov2_ptr, 0xaaaaaaaa as *const c_void, 10);
            let prov2 = prov2.assume_init();
            assert_eq!(prov2.alloc_id.get(), 4);
        }
    }

    #[test]
    fn bsan_malloc_allocmetadata_persistance() {
        let bsan_test_hooks = TEST_HOOKS.clone();
        unsafe {
            bsan_init(bsan_test_hooks);
            let mut prov1 = MaybeUninit::<Provenance>::uninit();
            let prov1_ptr = (&mut prov1) as *mut _;
            let span1 = 42;
            bsan_alloc(span1, prov1_ptr, 0xaaaaaaaa as *const c_void, 10);
            debug!("directly after bsan_malloc");
            let prov1 = prov1.assume_init();

            let prov_alloc_id = prov1.alloc_id;
            let alloc_metadata = prov1.lock_address as *const AllocMetadata;
            log::info!(
                "About to drop provenance. The alloc_metadata behind the lock address should be available afterward: {:?}",
                *alloc_metadata
            );
            drop(prov1);
            log::info!("Provenance dropped, alloc metadata is: {:?}", *alloc_metadata);

            let alloc_metadata = &*alloc_metadata;
            assert_eq!(alloc_metadata.alloc_id, prov_alloc_id);
        }
    }
}
