use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::alloc::{AllocError, Allocator, GlobalAlloc, Layout};
use core::cell::SyncUnsafeCell;
use core::ffi::CStr;
use core::fmt;
use core::fmt::{Write, write};
use core::mem::{self, zeroed};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::sync::atomic::AtomicUsize;

use hashbrown::{DefaultHashBuilder, HashMap};
use rustc_hash::FxBuildHasher;

use crate::BsanHooks;

/// Every action that requires a heap allocation must be performed through a globally
/// accessible, singleton instance of `GlobalContext`. Initializing or obtaining
/// a reference to this instance is unsafe, since it requires having been initialized
/// with a valid set of `BsanHooks`, which is provided from across the FFI.
/// Only shared references (&self) can be obtained, since this object will be concurrently
/// accessed. All of the API endpoints here can be soundly marked as safe under the assumption
/// that these invariants hold. This design pattern requires us to pass the `GlobalContext` instance
/// around explicitly, but it prevents us from relying on implicit global state and limits the spread
/// of unsafety throughout the library.
#[derive(Debug)]
pub struct GlobalContext {
    pub hooks: BsanHooks,
    next_alloc_id: AtomicUsize,
}

impl GlobalContext {
    /// Creates a new instance of `GlobalContext` using the given `BsanHooks`.
    /// This function will also initialize our shadow heap
    fn new(hooks: BsanHooks) -> Self {
        Self { hooks, next_alloc_id: AtomicUsize::new(1) }
    }

    /// Creates a new instance of `BVec<T>`, allocated using the
    /// `GlobalContext` instance as an `Allocator`.
    pub fn vec<T>(&self) -> BVec<T> {
        BVec::new()
    }

    /// Creates a new instance of `BVecDeque<T>`, which will be allocated using the
    /// `GlobalContext` instance as an `Allocator`.
    pub fn vecdeque<T>(&self) -> BVecDeque<T> {
        BVecDeque::new()
    }

    /// Prints a given set of formatted arguments. This function is not meant
    /// to be called directly; instead, it should be used with the `print!`,
    /// `println!`, and `ui_test!` macros.
    pub fn print(&self, args: fmt::Arguments<'_>) {
        let mut w = self.vec();
        let _ = write!(&mut w, "{}", args);
        unsafe {
            (self.hooks.print)(mem::transmute(w.as_ptr()));
        }
    }
}

/// Prints to stdout.
macro_rules! print {
    ($ctx:expr, $($arg:tt)*) => {{
        ctx.print(core::format_args!($($arg)*));
    }};
}
pub(crate) use print;

/// Prints to stdout, appending a newline.
macro_rules! println {
    ($ctx:expr) => {
        $crate::print!($ctx, "\n")
    };
    ($ctx:expr, $($arg:tt)*) => {{
        $ctx.print(core::format_args_nl!($($arg)*));
    }};
}
pub(crate) use println;

// General-purpose debug logging, which is only enabled in debug builds.
macro_rules! debug {
    ($ctx:expr, $($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::println!($ctx, $($arg)*);
    };
}
pub(crate) use debug;

// Logging for UI testing, which is enabled by the `ui_test` feature.
macro_rules! ui_test {
    ($ctx:expr, $($arg:tt)*) => {
        #[cfg(feature = "ui_test")]
        $crate::println!($ctx, $($arg)*);
    };
}
pub(crate) use ui_test;

unsafe impl Allocator for &GlobalContext {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        unsafe {
            match layout.size() {
                0 => Ok(NonNull::slice_from_raw_parts(layout.dangling(), 0)),
                // SAFETY: `layout` is non-zero in size,
                size => unsafe {
                    let raw_ptr: *mut u8 = mem::transmute((self.hooks.malloc)(layout.size()));
                    let ptr = NonNull::new(raw_ptr).ok_or(AllocError)?;
                    Ok(NonNull::slice_from_raw_parts(ptr, size))
                },
            }
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        (self.hooks.free)(mem::transmute(ptr.as_ptr()))
    }
}

/// A thin wrapper around `Vec` that uses `GlobalContext` as its allocator
#[derive(Debug, Clone)]
pub struct BVec<T>(Vec<T, &'static GlobalContext>);

impl<T> BVec<T> {
    fn new() -> Self {
        unsafe { Self(Vec::new_in(global_ctx())) }
    }
}

impl<T> Deref for BVec<T> {
    type Target = Vec<T, &'static GlobalContext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// We provide this trait implementation so that we can use `BVec` to
/// store the temporary results of formatting a string in the implementation
/// of `GlobalContext::print`
impl core::fmt::Write for BVec<u8> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.bytes();
        if self.try_reserve_exact(bytes.len()).is_err() {
            Err(core::fmt::Error)
        } else {
            self.extend(bytes);
            Ok(())
        }
    }
}

/// A thin wrapper around `VecDeque` that uses `GlobalContext` as its allocator
#[derive(Debug, Clone)]
pub struct BVecDeque<T>(VecDeque<T, &'static GlobalContext>);

impl<T> BVecDeque<T> {
    fn new() -> Self {
        unsafe { Self(VecDeque::new_in(global_ctx())) }
    }
}

impl<T> Deref for BVecDeque<T> {
    type Target = VecDeque<T, &'static GlobalContext>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for BVecDeque<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// The seed for the random state of the hash function for `BHashMap`.
/// Equal to the decimal encoding of the ascii for "BSAN".
static BSAN_HASH_SEED: usize = 1112752462;

/// A thin wrapper around `HashMap` that uses `GlobalContext` as its allocator
#[derive(Debug, Clone)]
pub struct BHashMap<K, V>(HashMap<K, V, FxBuildHasher, &'static GlobalContext>);

impl<K, V> BHashMap<K, V> {
    fn new() -> Self {
        unsafe { Self(HashMap::with_hasher_in(FxBuildHasher, global_ctx())) }
    }
}

impl<K, V> Deref for BHashMap<K, V> {
    type Target = HashMap<K, V, FxBuildHasher, &'static GlobalContext>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for BHashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// We need to declare a global allocator to be able to use `alloc` in a `#[no_std]`
/// crate. Anything other than the `GlobalContext` object will clash with the interceptors,
/// so we provide a placeholder that panics when it is used.
#[cfg(not(test))]
mod global_alloc {
    use core::alloc::{GlobalAlloc, Layout};

    #[derive(Default)]
    struct DummyAllocator;

    unsafe impl GlobalAlloc for DummyAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            panic!()
        }
        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            panic!()
        }
    }

    #[global_allocator]
    static GLOBAL_ALLOCATOR: DummyAllocator = DummyAllocator;
}

#[cfg(not(test))]
pub static GLOBAL_CTX: SyncUnsafeCell<Option<GlobalContext>> = SyncUnsafeCell::new(None);

#[cfg(test)]
pub static TEST_HOOKS: BsanHooks = BsanHooks {
    malloc: libc::malloc,
    free: libc::free,
    mmap: libc::mmap,
    munmap: libc::munmap,
    print: |ptr| unsafe {
        println!(mem::transmute::<&str>(ptr));
    },
};

/// A singleton instance of `GlobalContext`. All API functions
/// rely on this state to be initialized.
#[cfg(test)]
pub static GLOBAL_CTX: SyncUnsafeCell<Option<GlobalContext>> =
    SyncUnsafeCell::new(Some(GlobalContext::new(TEST_HOOKS)));

/// Initializes the global context object.
/// This function must only be called once: when the program is first initialized.
/// It is marked as `unsafe`, because it relies on the set of function pointers in
/// `BsanHooks` to be valid.
#[inline]
pub unsafe fn init_global_ctx(hooks: BsanHooks) -> &'static GlobalContext {
    *GLOBAL_CTX.get() = Some(GlobalContext::new(hooks));
    global_ctx()
}

/// Deinitializes the global context object.
/// This function must only be called once: when the program is terminating.
/// It is marked as `unsafe`, since all other API functions except for `bsan_init` rely
/// on the assumption that this function has not been called yet.
#[inline]
pub unsafe fn deinit_global_ctx() {
    drop((&mut *GLOBAL_CTX.get()).take());
}

/// Accessing the global context is unsafe since the user needs to ensure that
/// the context is initialized, e.g. `bsan_init` has been called and `bsan_deinit`
/// has not yet been called.
#[inline]
pub unsafe fn global_ctx() -> &'static GlobalContext {
    (&(*GLOBAL_CTX.get())).as_ref().unwrap_unchecked()
}
