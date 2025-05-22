use core::cmp::Ordering;
use core::cmp::Ordering::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RetagInfo {
    pub size: usize,
    pub perm_kind: Permission,
    pub protector_kind: ProtectorKind,
}

impl RetagInfo {
    #[inline]
    pub fn new(size: usize, perm_kind: Permission, protector_kind: ProtectorKind) -> Self {
        Self { size, perm_kind, protector_kind }
    }

    pub unsafe fn from_raw(size: usize, perm_kind: u8, protector_kind: u8) -> Self {
        let perm_kind = unsafe { Permission::from_raw(perm_kind) };
        let protector_kind = unsafe { ProtectorKind::from_raw(protector_kind) };
        Self::new(size, perm_kind, protector_kind)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtectorKind {
    NoProtector,
    /// Protected against aliasing violations from other pointers.
    ///
    /// Items protected like this cause UB when they are invalidated, *but* the pointer itself may
    /// still be used to issue a deallocation.
    ///
    /// This is required for LLVM IR pointers that are `noalias` but *not* `dereferenceable`.
    WeakProtector,

    /// Protected against any kind of invalidation.
    ///
    /// Items protected like this cause UB when they are invalidated or the memory is deallocated.
    /// This is strictly stronger protection than `WeakProtector`.
    ///
    /// This is required for LLVM IR pointers that are `dereferenceable` (and also allows `noalias`).
    StrongProtector,
}

impl ProtectorKind {
    unsafe fn from_raw(protector_kind: u8) -> Self {
        unsafe { core::mem::transmute::<u8, ProtectorKind>(protector_kind) }
    }
}

/// The activation states of a pointer.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PermissionPriv {
    /// represents: a local mutable reference that has not yet been written to;
    /// allows: child reads, foreign reads;
    /// affected by: child writes (becomes Active),
    /// rejects: foreign writes (Disabled).
    ///
    /// `ReservedFrz` is mostly for types that are `Freeze` (no interior mutability).
    /// If the type has interior mutability, see `ReservedIM` instead.
    /// (Note: since the discovery of `tests/fail/tree_borrows/reservedim_spurious_write.rs`,
    /// we also use `ReservedFreeze` for mutable references that were retagged with a protector
    /// independently of interior mutability)
    ///
    /// special case: beuse self::PermissionPriv::*;haves differently when protected, which is where `conflicted`
    /// is relevant
    /// - `conflicted` is set on foreign reads,
    /// - `conflicted` must not be set on child writes (there is UB otherwise).
    ///
    /// This is so that the behavior of `Reserved` adheres to the rules of `noalias`:
    /// - foreign-read then child-write is UB due to `conflicted`,
    /// - child-write then foreign-read is UB since child-write will activate and then
    ///   foreign-read disables a protected `Active`, which is UB.
    ReservedFrz,

    #[allow(dead_code)]
    ReservedFrzConf,
    /// Alternative version of `ReservedFrz` made for types with interior mutability.
    /// allows: child reads, foreign reads, foreign writes (extra);
    /// affected by: child writes (becomes Active);
    /// rejects: nothing.
    ReservedIM,
    /// represents: a unique pointer;
    /// allows: child reads, child writes;
    /// rejects: foreign reads (Frozen), foreign writes (Disabled).
    Active,
    /// represents: a shared pointer;
    /// allows: all read accesses;
    /// rejects child writes (UB), foreign writes (Disabled).
    Frozen,
    /// represents: a dead pointer;
    /// allows: all foreign accesses;
    /// rejects: all child accesses (UB).
    Disabled,
}
use self::PermissionPriv::*;

impl PartialOrd for PermissionPriv {
    /// PermissionPriv is ordered by the reflexive transitive closure of
    /// `Reserved(conflicted=false) < Reserved(conflicted=true) < Active < Frozen < Disabled`.
    /// `Reserved` that have incompatible `ty_is_freeze` are incomparable to each other.
    /// This ordering matches the reachability by transitions, as asserted by the exhaustive test
    /// `permissionpriv_partialord_is_reachability`.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(match (self, other) {
            (a, b) if a == b => Equal,
            (Disabled, _) => Greater,
            (_, Disabled) => Less,
            (Frozen, _) => Greater,
            (_, Frozen) => Less,
            (Active, _) => Greater,
            (_, Active) => Less,
            (ReservedIM, ReservedIM) => Equal,
            (ReservedFrz, ReservedFrz) => Equal,
            (ReservedFrzConf, ReservedFrzConf) => Equal,
            (ReservedFrz, ReservedFrzConf) => Less,
            // Versions of `Reserved` with different interior mutability are incomparable with each
            // other.
            (ReservedFrzConf, ReservedFrz) => Greater,
            (ReservedIM, ReservedFrz) | (ReservedFrz, ReservedIM) => return None,
            (ReservedIM, ReservedFrzConf) | (ReservedFrzConf, ReservedIM) => return None,
        })
    }
}

impl PermissionPriv {
    /// Check if `self` can be the initial state of a pointer.
    fn is_initial(&self) -> bool {
        matches!(self, ReservedFrz | Frozen | ReservedIM)
    }

    /// Reject `ReservedIM` that cannot exist in the presence of a protector.
    fn compatible_with_protector(&self) -> bool {
        !matches!(self, ReservedIM)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

pub struct Permission {
    inner: PermissionPriv,
}
impl Permission {
    #[inline]
    pub unsafe fn from_raw(perm_priv: u8) -> Self {
        let inner: PermissionPriv =
            unsafe { core::mem::transmute::<u8, PermissionPriv>(perm_priv) };
        Self { inner }
    }

    /// Check if `self` can be the initial state of a pointer.
    pub fn is_initial(&self) -> bool {
        self.inner.is_initial()
    }
    /// Check if `self` is the terminal state of a pointer (is `Disabled`).
    pub fn is_disabled(&self) -> bool {
        self.inner == Disabled
    }
    /// Check if `self` is the post-child-write state of a pointer (is `Active`).
    pub fn is_active(&self) -> bool {
        self.inner == Active
    }

    /// Default initial permission of the root of a new tree at inbounds positions.
    /// Must *only* be used for the root, this is not in general an "initial" permission!
    pub fn new_active() -> Self {
        Self { inner: Active }
    }

    /// Default initial permission of a reborrowed mutable reference that is either
    /// protected or not interior mutable.
    fn new_reserved_frz() -> Self {
        Self { inner: ReservedFrz }
    }

    /// Default initial permission of an unprotected interior mutable reference.
    fn new_reserved_im() -> Self {
        Self { inner: ReservedIM }
    }

    /// Wrapper around `new_reserved_frz` and `new_reserved_im` that decides
    /// which to call based on the interior mutability and the retag kind (whether there
    /// is a protector is relevant because being protected takes priority over being
    /// interior mutable)
    pub fn new_reserved(ty_is_freeze: bool, protected: bool) -> Self {
        if ty_is_freeze || protected { Self::new_reserved_frz() } else { Self::new_reserved_im() }
    }

    /// Default initial permission of a reborrowed shared reference.
    pub fn new_frozen() -> Self {
        Self { inner: Frozen }
    }

    /// Default initial permission of  the root of a new tree at out-of-bounds positions.
    /// Must *only* be used for the root, this is not in general an "initial" permission!
    pub fn new_disabled() -> Self {
        Self { inner: Disabled }
    }

    /// Reject `ReservedIM` that cannot exist in the presence of a protector.
    pub fn compatible_with_protector(&self) -> bool {
        self.inner.compatible_with_protector()
    }
}

impl Into<u8> for Permission {
    fn into(self) -> u8 {
        self.inner as u8
    }
}
