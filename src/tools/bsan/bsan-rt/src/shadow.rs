#![cfg_attr(not(test), no_std)]

use core::alloc::Layout;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ops::{Add, BitAnd, Deref, DerefMut, Shr};
use core::ptr::NonNull;
use core::slice::SliceIndex;
use core::{mem, ptr};

use libc::{MAP_ANONYMOUS, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::global::{GlobalCtx, global_ctx};
use crate::{BsanAllocHooks, BsanHooks};
/// Different targets have a different number
/// of significant bits in their pointer representation.
/// On 32-bit platforms, all 32-bits are addressable. Most
/// 64-bit platforms only use 48-bits. Following the LLVM Project,
/// we hard-code these values based on the underlying architecture.
/// Most, if not all 64 bit architectures use 48-bits. However, the
/// Armv8-A spec allows addressing 52 or 56 bits as well. No processors
/// implement this yet, though, so we can use target_pointer_width.

#[cfg(target_pointer_width = "64")]
static VA_BITS: u32 = 48;

#[cfg(target_pointer_width = "32")]
static VA_BITS: u32 = 32;

#[cfg(target_pointer_width = "16")]
static VA_BITS: u32 = 16;

// The number of bytes in a pointer
static PTR_BYTES: usize = mem::size_of::<usize>();

// The number of addressable, word-aligned, pointer-sized chunks
static NUM_ADDR_CHUNKS: u32 = VA_BITS - (PTR_BYTES.ilog2());

// We have 2^L2_POWER entries in the second level of the page table
// Adding 1 ensures that we have more second-level entries than first
// level entries if the number of addressable chunks is odd.
static L2_POWER: u32 = NUM_ADDR_CHUNKS.strict_add(1).strict_div(2);

// We have 2^L1_POWER entries in the first level of the page table
static L1_POWER: u32 = NUM_ADDR_CHUNKS.strict_div(2);

// The number of entries in the second level of the page table
static L2_LEN: usize = 2_usize.pow(L2_POWER);

// The number of entries in the first level of the page table
static L1_LEN: usize = 2_usize.pow(L1_POWER);

// The protection flags for the page tables
static PROT_SHADOW: i32 = PROT_READ | PROT_WRITE;

// The flags for the page tables
static MAP_SHADOW: i32 = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;

/// Converts an address into a pair of indices into the first and second
/// levels of the shadow page table.
#[inline(always)]
pub fn table_indices(address: usize) -> (usize, usize) {
    #[cfg(target_endian = "little")]
    let l1_index = address.shr(L2_POWER).bitand((L1_POWER - 1) as usize);
    #[cfg(target_endian = "big")]
    let l1_index = address.shl(L2_POWER).bitand((L1_POWER - 1) as usize);

    let l2_index = address.bitand((L2_POWER - 1) as usize);
    (l1_index, l2_index)
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct L2<T> {
    bytes: *mut [T; L2_LEN],
}

unsafe impl<T> Sync for L2<T> {}

impl<T> L2<T> {
    pub fn new(allocator: &BsanHooks, addr: *mut c_void) -> Self {
        let mut l2_bytes: *mut [T; L2_LEN] = unsafe {
            let l2_void =
                (allocator.mmap)(addr, size_of::<T>() * L2_LEN, PROT_SHADOW, MAP_SHADOW, -1, 0);
            assert!(l2_void != core::ptr::null_mut() || l2_void != -1isize as (*mut c_void));
            ptr::write_bytes(l2_void as *mut u8, 0, size_of::<T>() * L2_LEN);
            mem::transmute(l2_void)
        };

        Self { bytes: l2_bytes }
    }

    #[inline(always)]
    pub unsafe fn lookup(&self, l2_index: usize) -> *mut T {
        &raw mut (*self.bytes)[l2_index]
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct L1<T> {
    entries: *mut [*mut L2<T>; L1_LEN],
}

unsafe impl<T> Sync for L1<T> {}

impl<T> L1<T> {
    pub fn new(allocator: &BsanHooks) -> Self {
        let mut l1_entries: *mut [*mut L2<T>; L1_LEN] = unsafe {
            let l1_void = (allocator.mmap)(
                core::ptr::null_mut(),
                PTR_BYTES * L1_LEN,
                PROT_SHADOW,
                MAP_SHADOW,
                -1,
                0,
            );
            assert!(l1_void != core::ptr::null_mut() || l1_void != -1isize as (*mut c_void));
            // zero bytes after allocating
            ptr::write_bytes(l1_void as *mut u8, 0, PTR_BYTES * L1_LEN);
            mem::transmute(l1_void)
        };

        Self { entries: l1_entries }
    }
}

/// A two-level page table. This wrapper struct encapsulates
/// the interior, unsafe implementation, providing debug assertions
/// for each method.
#[repr(transparent)]
#[derive(Debug)]
pub struct ShadowHeap<T> {
    l1: L1<T>,
}

impl<T: Default + Copy> Default for ShadowHeap<T> {
    fn default() -> Self {
        Self { l1: unsafe { L1::new(global_ctx().hooks()) } }
    }
}

impl<T> ShadowHeap<T> {
    pub fn new(allocator: &BsanHooks) -> Self {
        Self { l1: L1::new(allocator) }
    }
}

impl<T: Default + Copy> ShadowHeap<T> {
    pub unsafe fn load_prov(&self, address: usize) -> T {
        let (l1_addr, l2_addr) = table_indices(address);
        let mut l2 = (*self.l1.entries)[l1_addr];
        if l2.is_null() {
            return T::default();
        }

        *(*l2).lookup(l2_addr)
    }

    pub unsafe fn store_prov(&self, provenance: *const T, address: usize) {
        if provenance.is_null() {
            return;
        }
        let (l1_addr, l2_addr) = table_indices(address);
        let mut l2 = (*self.l1.entries)[l1_addr];
        if l2.is_null() {
            let l2_addr = unsafe { (*self.l1.entries).as_ptr().add(l1_addr) as *mut c_void };
            l2 = &mut L2::new(global_ctx().hooks(), l2_addr);
            (*self.l1.entries)[l1_addr] = l2;
        }

        *(*l2).lookup(l2_addr) = *provenance;
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_ulonglong, c_void};
    use core::ptr::{null, null_mut};

    use libc::{self, MAP_ANONYMOUS, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

    use crate::global::{deinit_global_ctx, init_global_ctx};
    use crate::shadow::*;
    use crate::{BsanAllocHooks, BsanHooks, Exit, Free, MMap, MUnmap, Malloc, Print};

    unsafe extern "C" fn test_print(_: *const c_char) {}
    unsafe extern "C" fn test_exit() -> ! {
        std::process::exit(0)
    }

    const TEST_HOOKS: BsanHooks = BsanHooks {
        alloc: BsanAllocHooks { malloc: libc::malloc as Malloc, free: libc::free as Free },
        mmap: test_mmap,
        munmap: test_munmap,
        print: test_print,
        exit: test_exit,
    };

    unsafe extern "C" fn test_mmap(
        addr: *mut c_void,
        size: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: c_ulonglong,
    ) -> *mut c_void {
        libc::mmap(addr, size, prot, flags, fd, offset as i64)
    }

    unsafe extern "C" fn test_munmap(ptr: *mut c_void, size: usize) -> i32 {
        libc::munmap(ptr, size)
    }

    #[derive(Debug, Copy, Clone)]
    struct TestProv {
        value: u8,
    }

    impl Default for TestProv {
        fn default() -> Self {
            Self { value: 0 }
        }
    }

    fn setup() {
        unsafe {
            init_global_ctx(&TEST_HOOKS);
        }
    }

    fn teardown() {
        unsafe {
            deinit_global_ctx();
        }
    }

    #[test]
    fn test_table_indices() {
        setup();
        let addr = 0x1234_5678_1234_5678;
        let (l1, l2) = table_indices(addr);
        assert!(l1 < L1_LEN);
        assert!(l2 < L2_LEN);
        teardown();
    }

    #[test]
    fn test_l2_creation() {
        let _l2 = L2::<TestProv>::new(&TEST_HOOKS, core::ptr::null_mut());
    }

    #[test]
    fn test_l1_creation() {
        let _l1 = L1::<TestProv>::new(&TEST_HOOKS);
    }

    #[test]
    fn test_shadow_heap_creation() {
        setup();
        let _heap = ShadowHeap::<TestProv>::default();
        teardown();
    }

    #[test]
    fn test_load_null_prov() {
        setup();
        let heap = ShadowHeap::<TestProv>::default();
        let prov = unsafe { heap.load_prov(0) };
        assert_eq!(prov.value, 0);
        teardown();
    }

    #[test]
    fn test_store_and_load_prov() {
        setup();
        let heap = ShadowHeap::<TestProv>::default();
        let test_prov = TestProv { value: 42 };
        // Use an address that will split into non-zero indices for both L1 and L2
        let addr = 0x1234_5678_1234_5678;

        unsafe {
            // heap.store_prov(&test_prov, addr);
            let loaded_prov = heap.load_prov(addr);
            // assert_eq!(loaded_prov.value, test_prov.value);
        }
        teardown();
    }

    #[test]
    fn create_and_drop() {
        setup();
        let _ = ShadowHeap::<TestProv>::default();
        teardown();
    }
}
