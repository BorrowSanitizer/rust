use core::cell::SyncUnsafeCell;
use core::sync::atomic::AtomicUsize;

#[cfg(test)]
use crate::TEST_ALLOC;
use crate::shadow::ShadowHeap;
use crate::{BsanAllocator, Provenance};

#[derive(Debug)]
pub struct GlobalContext {
    pub allocator: BsanAllocator,
    pub next_alloc_id: AtomicUsize,
    pub shadow_heap: ShadowHeap<Provenance>,
}

impl GlobalContext {
    fn new(allocator: BsanAllocator) -> Self {
        Self {
            allocator,
            next_alloc_id: AtomicUsize::new(1),
            shadow_heap: ShadowHeap::new(allocator),
        }
    }
}

pub static GLOBAL_CTX: SyncUnsafeCell<Option<GlobalContext>> = SyncUnsafeCell::new(None);

pub unsafe fn init_global_ctx(alloc: BsanAllocator) {
    *GLOBAL_CTX.get() = Some(GlobalContext::new(alloc));
}

#[inline]
pub unsafe fn global_ctx() -> &'static GlobalContext {
    (&(*GLOBAL_CTX.get())).as_ref().unwrap_unchecked()
}
