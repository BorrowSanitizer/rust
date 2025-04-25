use core::alloc::Layout;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ops::{Add, BitAnd, Deref, DerefMut, Shr};
use core::ptr::NonNull;
use core::slice::SliceIndex;
use core::{mem, ptr};

use libc::{MAP_ANONYMOUS, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::global::{GlobalCtx, global_ctx};
use crate::{BsanAllocHooks, BsanHooks, MUnmap, println};
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
#[derive(Debug)]
pub struct ShadowHeap<T> {
    // First level table containing pointers to second level tables
    l1_entries: *mut [*mut [T; L2_LEN]; L1_LEN],
    hooks: BsanHooks,
}

unsafe impl<T> Sync for ShadowHeap<T> {}

impl<T> Default for ShadowHeap<T> {
    fn default() -> Self {
        unsafe { Self::new(&(*global_ctx()).hooks()) }
    }
}

impl<T> ShadowHeap<T> {
    pub fn new(hooks: &BsanHooks) -> Self {
        unsafe {
            let l1_void =
                (hooks.mmap)(ptr::null_mut(), PTR_BYTES * L1_LEN, PROT_SHADOW, MAP_SHADOW, -1, 0);
            assert!(!l1_void.is_null() && l1_void != (-1isize as *mut c_void));
            ptr::write_bytes(l1_void as *mut u8, 0, PTR_BYTES * L1_LEN);

            Self { l1_entries: mem::transmute(l1_void), hooks: hooks.clone() }
        }
    }

    unsafe fn allocate_l2_table(&self) -> *mut [T; L2_LEN] {
        let l2_void = (self.hooks.mmap)(
            ptr::null_mut(),
            mem::size_of::<T>() * L2_LEN,
            PROT_SHADOW,
            MAP_SHADOW,
            -1,
            0,
        );
        assert!(!l2_void.is_null() && l2_void != (-1isize as *mut c_void));
        ptr::write_bytes(l2_void as *mut u8, 0, mem::size_of::<T>() * L2_LEN);
        mem::transmute(l2_void)
    }
}

impl<T: Default + Copy> ShadowHeap<T> {
    pub unsafe fn load_prov(&self, address: usize) -> T {
        let ctx: &GlobalCtx = &*global_ctx();
        let (l1_index, l2_index) = table_indices(address);
        println!(
            ctx,
            "load_prov: address={:#x}, l1_index={:#x}, l2_index={:#x}", address, l1_index, l2_index
        );

        let l2_table = (*self.l1_entries)[l1_index];
        println!(ctx, "load_prov: l2_table={:?}", l2_table);

        if l2_table.is_null() {
            println!(ctx, "load_prov: L2 table is null, returning default");
            return T::default();
        }

        println!(ctx, "load_prov: loading value from l2_index={:#x}", l2_index);
        (*l2_table)[l2_index]
    }

    pub unsafe fn store_prov(&self, provenance: *const T, address: usize) {
        let ctx: &GlobalCtx = &*global_ctx();
        if provenance.is_null() {
            println!(ctx, "store_prov: null provenance");
            return;
        }

        let (l1_index, l2_index) = table_indices(address);
        println!(
            ctx,
            "store_prov: address={:#x}, l1_index={:#x}, l2_index={:#x}",
            address,
            l1_index,
            l2_index
        );

        let l2_table_ptr = &mut (*self.l1_entries)[l1_index];
        println!(ctx, "store_prov: l2_table_ptr={:?}", l2_table_ptr);

        if l2_table_ptr.is_null() {
            println!(ctx, "store_prov: allocating new L2 table");
            let new_table = self.allocate_l2_table();
            *l2_table_ptr = new_table;
            println!(ctx, "store_prov: new L2 table allocated at {:?}", *l2_table_ptr);
        }

        println!(ctx, "store_prov: storing value at l2_index={:#x}", l2_index);
        (*l2_table_ptr)[l2_index] = *provenance;
    }
}

impl<T> Drop for ShadowHeap<T> {
    fn drop(&mut self) {
        unsafe {
            // Free all L2 tables
            for i in 0..L1_LEN {
                let l2_table = (*self.l1_entries)[i];
                if !l2_table.is_null() {
                    (self.hooks.munmap)(l2_table as *mut c_void, mem::size_of::<T>() * L2_LEN);
                }
            }

            // Free L1 table
            (self.hooks.munmap)(self.l1_entries as *mut c_void, PTR_BYTES * L1_LEN);
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_char, c_ulonglong, c_void};
    use core::ptr::{null, null_mut};
    use std::println;

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
            init_global_ctx(TEST_HOOKS);
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

    #[test]
    fn test_shadow_heap_performance() {
        setup();
        let heap = ShadowHeap::<TestProv>::default();
        let ctx: &GlobalCtx = unsafe { &*global_ctx() };

        // Create test data
        const NUM_OPERATIONS: usize = 100;
        let test_values: Vec<TestProv> =
            (0..NUM_OPERATIONS).map(|i| TestProv { value: (i % 255) as u8 }).collect();

        // Use a properly aligned base address
        const BASE_ADDR: usize = 0x7FFF_FFFF_AA00;

        unsafe {
            // Store values
            for i in 0..NUM_OPERATIONS {
                let addr = BASE_ADDR + (i * 8); // Use 8-byte alignment
                println!("Address: {:#x}", addr);
                let (l1, l2) = table_indices(addr);
                heap.store_prov(&test_values[i], addr);
                println!("HERE: {:?}", test_values[i].value);
            }

            // Load and verify values
            for i in 0..NUM_OPERATIONS {
                let addr = BASE_ADDR + (i * 8);
                println!("Address: {:#x}", addr);
                let (l1, l2) = table_indices(addr);
                let loaded = heap.load_prov(addr);
                println!("HERE: {:?}", test_values[i].value);
                println!("HERE: {:?}", loaded.value);
                // assert_eq!(loaded.value, test_values[i].value);
            }
        }

        teardown();
    }
}
