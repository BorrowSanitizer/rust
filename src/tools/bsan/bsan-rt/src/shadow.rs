use core::alloc::Layout;
use core::iter::repeat_n;
use core::marker::PhantomData;
use core::mem;
use core::ops::{Add, BitAnd, Deref, DerefMut, Shr};

use crate::Provenance;

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

// The number of bytes in a pointer
static PTR_BYTES: usize = mem::size_of::<usize>();

// 2^NUM_ADDR_CHUNKS is the number of addressable, pointer-sized,
// word-aligned chunks.
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

/// Converts an address into a pair of indices into the first and second
/// levels of the shadow page table.
#[inline(always)]
fn table_indices(address: usize) -> (usize, usize) {
    #[cfg(target_endian = "little")]
    let l1_index = address.shr(L2_POWER).bitand((L1_POWER - 1) as usize);

    #[cfg(target_endian = "big")]
    let l1_index = address.shl(L2_POWER).bitand((L1_POWER - 1) as usize);

    let l2_index = address.bitand((L2_POWER - 1) as usize);

    (l1_index, l2_index)
}

#[repr(C)]
pub struct L2 {
    bytes: [Provenance; L2_LEN],
}

impl L2 {
    #[inline(always)]
    unsafe fn lookup_mut(&mut self, index: usize) -> &mut Provenance {
        self.bytes.get_unchecked_mut(index)
    }
    #[inline(always)]
    unsafe fn lookup(&mut self, index: usize) -> &Provenance {
        self.bytes.get_unchecked(index)
    }
}

#[repr(C)]
pub struct L1 {
    entries: [*mut L2; L1_LEN],
}

impl L1 {
    fn new() -> Self {
        Self { entries: [core::ptr::null_mut(); L1_LEN] }
    }

    #[inline(always)]
    unsafe fn lookup_mut(&mut self, index: usize) -> Option<&mut Provenance> {
        let (l1_index, l2_index) = table_indices(index);
        let l2 = self.entries.get_unchecked_mut(l1_index);
        if l2.is_null() { None } else { Some((**l2).lookup_mut(l2_index)) }
    }

    #[inline(always)]
    unsafe fn lookup(&mut self, index: usize) -> Option<&Provenance> {
        let (l1_index, l2_index) = table_indices(index);
        let l2 = self.entries.get_unchecked(l1_index);
        if l2.is_null() { None } else { Some((**l2).lookup(l2_index)) }
    }
}

/// A two-level page table. This wrapper struct encapsulates
/// the interior, unsafe implementation, providing debug assertions
/// for each method.
#[repr(transparent)]
pub struct ShadowHeap {
    l1: L1,
}

impl Default for ShadowHeap {
    fn default() -> Self {
        let l1 = L1::new();
        Self { l1 }
    }
}

impl Deref for ShadowHeap {
    type Target = L1;
    fn deref(&self) -> &Self::Target {
        &self.l1
    }
}

impl DerefMut for ShadowHeap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.l1
    }
}

mod tests {
    use super::*;
    #[test]
    fn create_and_drop() {
        let _ = ShadowHeap::default();
    }
}
