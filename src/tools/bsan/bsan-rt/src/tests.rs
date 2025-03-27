#[cfg(test)]
use crate::*;

#[test]
fn create_and_drop() {
    let _ = ShadowHeap::default();
}
