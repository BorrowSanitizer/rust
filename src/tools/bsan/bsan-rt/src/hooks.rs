use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::ffi::{c_char, c_ulonglong, c_void};
use core::num::NonZeroUsize;
use core::ptr::NonNull;
use core::sync::atomic::AtomicPtr;

use crate::block::*;
use crate::*;

pub type MMap = unsafe extern "C" fn(*mut c_void, usize, i32, i32, i32, c_ulonglong) -> *mut c_void;
pub type MUnmap = unsafe extern "C" fn(*mut c_void, usize) -> i32;
pub type Malloc = unsafe extern "C" fn(usize) -> *mut c_void;
pub type Free = unsafe extern "C" fn(*mut c_void);
pub type Print = unsafe extern "C" fn(*const c_char);
pub type Exit = unsafe extern "C" fn() -> !;

const BSAN_MMAP_PROT: i32 = libc::PROT_READ | libc::PROT_WRITE;
const BSAN_MMAP_FLAGS: i32 = libc::MAP_ANONYMOUS | libc::MAP_PRIVATE;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Hooks {
    pub alloc: AllocHooks,
    pub mmap: MMapHooks,
    pub print: Print,
    pub exit: Exit,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AllocHooks {
    malloc: Malloc,
    free: Free,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MMapHooks {
    mmap: MMap,
    munmap: MUnmap,
}

/// An mmap-ed chunk of memory that will munmap the chunk on drop.
#[derive(Debug)]
pub struct Block<T: Sized> {
    size: NonZeroUsize,
    base: NonNull<T>,
    next: AtomicPtr<Block<T>>,
    munmap: MUnmap,
}

impl<T: Sized> Block<T> {
    /// The last valid, addressable location within the block (at its high-end)
    #[inline]
    pub fn last(&self) -> *mut T {
        unsafe { self.base.as_ptr().add(self.size.get() - 1) }
    }

    /// The first valid, addressable location within the block (at its low-end)
    #[inline]
    pub fn first(&self) -> *mut T {
        self.base.as_ptr()
    }

    #[inline]
    pub fn get(&self, offset: usize) -> *mut T {
        assert!(offset < self.size.get(), "Block offset out of bounds");
        self.get_unchecked(offset)
    }

    #[inline]
    fn get_unchecked(&self, offset: usize) -> *mut T {
        debug_assert!(offset < self.size.get(), "Block offset out of bounds");
        unsafe { self.base.as_ptr().add(offset) }
    }
}

impl<T> Drop for Block<T> {
    fn drop(&mut self) {
        // SAFETY: our munmap pointer will be valid by construction of the GlobalCtx.
        // We can safely transmute it to c_void since that's what it was originally when
        // it was allocated by mmap
        let success = unsafe { (self.munmap)(mem::transmute(self.base.as_ptr()), self.size.get()) };
        if success != 0 {
            panic!("Failed to unmap block!");
        }
    }
}

impl MMapHooks {
    pub fn block<T>(&self, num_elements: usize) -> Block<T> {
        let layout = Layout::array::<T>(num_elements.into()).unwrap();
        let size = NonZeroUsize::new(layout.size()).unwrap();
        let base = unsafe {
            (self.mmap)(ptr::null_mut(), layout.size(), BSAN_MMAP_PROT, BSAN_MMAP_FLAGS, -1, 0)
        };
        if base.is_null() {
            panic!("Allocation failed");
        }
        let base = unsafe { NonNull::new_unchecked(mem::transmute(base)) };
        let munmap = self.munmap;
        Block { size, base, munmap, next: AtomicPtr::new(ptr::null_mut()) }
    }
}

unsafe impl Allocator for AllocHooks {
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

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::*;

    unsafe extern "C" fn test_print(ptr: *const c_char) {
        std::println!("{}", std::ffi::CStr::from_ptr(ptr).to_str().expect("Invalid UTF-8"));
    }

    unsafe extern "C" fn test_exit() -> ! {
        std::process::exit(0);
    }

    unsafe extern "C" fn test_mmap(
        addr: *mut c_void,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: u64,
    ) -> *mut c_void {
        // LLVM's sanitizer API uses u64 for OFF_T, but libc uses i64
        // We use this wrapper function to avoid having to manually update
        // the bindings.
        libc::mmap(addr, len, prot, flags, fd, offset as i64)
    }

    pub static TEST_HOOKS: Hooks = Hooks {
        alloc: AllocHooks { malloc: libc::malloc, free: libc::free },
        mmap: MMapHooks { mmap: test_mmap, munmap: libc::munmap },
        print: test_print,
        exit: test_exit,
    };
}
