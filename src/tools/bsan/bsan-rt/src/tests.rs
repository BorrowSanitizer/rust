use core::ptr::{null, null_mut};

use libc::{MAP_ANONYMOUS, MAP_NORESERVE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

use crate::BsanAllocator;
use crate::shadow::*;

#[derive(Debug, Copy, Clone)]
struct TestProv {
    value: u8,
}

impl Default for TestProv {
    fn default() -> Self {
        Self { value: 0 }
    }
}

impl Provenance for TestProv {}

#[test]
fn test_table_indices() {
    let addr = 0x1234_5678;
    let (l1, l2) = table_indices(addr);
    assert!(l1 < L1_LEN);
    assert!(l2 < L2_LEN);
}

#[test]
fn test_l2_creation() {
    let allocator = BsanAllocator {
        mmap: |addr, size, prot, flags, fd, offset| {
            assert!(addr.is_null());
            assert!(size > 0);
            assert_eq!(prot, PROT_READ | PROT_WRITE);
            assert_eq!(flags, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE);
            assert_eq!(fd, -1);
            assert_eq!(offset, 0);
            // Return a dummy pointer for testing
            addr
        },
        malloc: |size| {
            assert!(size > 0);
            null_mut()
        },
        free: |ptr| {
            assert!(!ptr.is_null());
        },
        munmap: |ptr, size| {
            assert!(!ptr.is_null());
            assert!(size > 0);
        },
    };
    let _l2 = L2::<TestProv>::new(allocator);
}

#[test]
fn test_l1_creation() {
    let allocator = BsanAllocator {
        mmap: |addr, size, prot, flags, fd, offset| {
            assert!(addr.is_null());
            assert!(size > 0);
            assert_eq!(prot, PROT_READ | PROT_WRITE);
            assert_eq!(flags, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE);
            assert_eq!(fd, -1);
            assert_eq!(offset, 0);
            // Return a dummy pointer for testing
            addr
        },
        malloc: |size| {
            assert!(size > 0);
            null_mut()
        },
        free: |ptr| {
            assert!(!ptr.is_null());
        },
        munmap: |ptr, size| {
            assert!(!ptr.is_null());
            assert!(size > 0);
        },
    };
    let _l1 = L1::<TestProv>::new(allocator);
}

#[test]
fn test_shadow_heap_creation() {
    let _heap = ShadowHeap::<TestProv>::default();
}

#[test]
fn test_load_null_prov() {
    let mut heap = ShadowHeap::<TestProv>::default();
    let prov = unsafe { heap.load_prov(null()) };
    assert_eq!(prov.value, 0);
}

#[test]
fn test_store_and_load_prov() {
    let mut heap = ShadowHeap::<TestProv>::default();
    let test_prov = TestProv { value: 42 };
    let addr = 0x1000;
    

    unsafe {
        heap.store_prov(&test_prov, addr);
        let loaded_prov = heap.load_prov(addr as *mut c_void);
        assert_eq!(loaded_prov.value, test_prov.value);
    }
}