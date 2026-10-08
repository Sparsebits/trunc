//! Binary Merkle tree over per-block BLAKE3 digests.
//!
//! - leaf node  = BLAKE3(0x00 || leaf_digest)
//! - inner node = BLAKE3(0x01 || left || right)
//! - an odd node at the end of a level is promoted unchanged to the next level
//! - the root of zero leaves is BLAKE3(0x02)
//!
//! Domain-separation bytes prevent a leaf from being reinterpreted as an inner node.

use crate::Digest;

fn leaf(d: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(d);
    *h.finalize().as_bytes()
}

fn node(l: &Digest, r: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&[0x01]);
    h.update(l);
    h.update(r);
    *h.finalize().as_bytes()
}

fn empty_root() -> Digest {
    *blake3::hash(&[0x02]).as_bytes()
}

/// Merkle root over `leaves` (in order).
pub fn root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<Digest> = leaves.iter().map(leaf).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                [single] => *single,
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            })
            .collect();
    }
    level[0]
}

/// One step of an inclusion proof: the sibling digest and whether it sits on the left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Digest,
    pub sibling_is_left: bool,
}

/// Inclusion proof for `leaves[index]`. Returns `None` if `index` is out of range.
pub fn proof(leaves: &[Digest], index: usize) -> Option<Vec<ProofStep>> {
    if index >= leaves.len() {
        return None;
    }
    let mut steps = Vec::new();
    let mut level: Vec<Digest> = leaves.iter().map(leaf).collect();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = idx ^ 1;
        if sibling < level.len() {
            steps.push(ProofStep {
                sibling: level[sibling],
                sibling_is_left: sibling < idx,
            });
        }
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                [single] => *single,
                _ => unreachable!("chunks(2) yields 1 or 2 items"),
            })
            .collect();
        idx /= 2;
    }
    Some(steps)
}

/// Check that `leaf_digest` is included under `expected_root` via `steps`.
pub fn verify(leaf_digest: &Digest, steps: &[ProofStep], expected_root: &Digest) -> bool {
    let mut acc = leaf(leaf_digest);
    for s in steps {
        acc = if s.sibling_is_left {
            node(&s.sibling, &acc)
        } else {
            node(&acc, &s.sibling)
        };
    }
    &acc == expected_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn leaves(n: usize) -> Vec<Digest> {
        (0..n)
            .map(|i| crate::blake3(&(i as u64).to_le_bytes()))
            .collect()
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(root(&[]), empty_root());
        let l = leaves(1);
        assert_eq!(root(&l), leaf(&l[0]));
        assert!(verify(&l[0], &proof(&l, 0).unwrap(), &root(&l)));
    }

    #[test]
    fn order_matters() {
        let mut l = leaves(4);
        let r1 = root(&l);
        l.swap(1, 2);
        assert_ne!(r1, root(&l));
    }

    #[test]
    fn out_of_range_proof() {
        assert!(proof(&leaves(3), 3).is_none());
    }

    proptest! {
        #[test]
        fn every_leaf_proves(n in 1usize..70, pick in 0usize..70) {
            let l = leaves(n);
            let idx = pick % n;
            let r = root(&l);
            let p = proof(&l, idx).unwrap();
            prop_assert!(verify(&l[idx], &p, &r));
            // A different leaf must not verify with the same proof.
            let wrong = crate::blake3(b"not a leaf");
            prop_assert!(!verify(&wrong, &p, &r));
        }
    }
}
