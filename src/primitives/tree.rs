// from https://github.com/zcash/orchard/blob/main/src/tree.rs

#![allow(dead_code)]

use pasta_curves::pallas;

use ff::{Field, PrimeField, PrimeFieldBits};
use lazy_static::lazy_static;
use rand::RngCore;
use serde::de::{Deserializer, Error};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::iter;
use subtle::{Choice, ConditionallySelectable, CtOption};

use halo2_gadgets::primitives::sinsemilla::HashDomain;
use incrementalmerkletree::{Altitude, Hashable};

use super::commitment::*;
use super::utils::*;
use crate::consts::*;
use crate::global;

lazy_static! {
    pub static ref EMPTY_ROOTS: Vec<DomainMerkleHash> = {
        iter::empty()
            .chain(Some(DomainMerkleHash::empty_leaf()))
            .chain(
                (0..MERKLE_DEPTH).scan(DomainMerkleHash::empty_leaf(), |state, l| {
                    let l = l as u8;
                    *state = DomainMerkleHash::combine(l.into(), state, state);
                    Some(*state)
                }),
            )
            .collect()
    };
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DomainMerkleHash(pallas::Base);

impl DomainMerkleHash {
    pub fn from_cmx(cmx: &ExtractedCommitment) -> Self {
        DomainMerkleHash(cmx.value())
    }

    pub fn value(&self) -> pallas::Base {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(DomainMerkleHash)
    }
}

impl ConditionallySelectable for DomainMerkleHash {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        DomainMerkleHash(pallas::Base::conditional_select(&a.0, &b.0, choice))
    }
}

impl Hashable for DomainMerkleHash {
    fn empty_leaf() -> Self {
        DomainMerkleHash(pallas::Base::from(2))
    }

    fn combine(altitude: Altitude, left: &Self, right: &Self) -> Self {
        // MerkleCRH Sinsemilla hash domain.
        let domain = HashDomain::new(&global::get_domain_name(DOMAIN_MERKLECRH));

        DomainMerkleHash(
            domain
                .hash(
                    iter::empty()
                        .chain(i2lebsp_k(altitude.into()).iter().copied())
                        .chain(left.0.to_le_bits().iter().by_val().take(L_MERKLE))
                        .chain(right.0.to_le_bits().iter().by_val().take(L_MERKLE)),
                )
                .unwrap_or(pallas::Base::zero()),
        )
    }

    fn empty_root(altitude: Altitude) -> Self {
        EMPTY_ROOTS[<usize>::from(altitude)]
    }
}

impl Serialize for DomainMerkleHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DomainMerkleHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let parsed = <[u8; 32]>::deserialize(deserializer)?;
        <Option<_>>::from(Self::from_bytes(&parsed)).ok_or_else(|| {
            Error::custom(
            "Attempted to deserialize a non-canonical representation of a Pallas base field element.",
        )
        })
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct Anchor(pallas::Base);

impl From<pallas::Base> for Anchor {
    fn from(anchor_field: pallas::Base) -> Anchor {
        Anchor(anchor_field)
    }
}

impl From<DomainMerkleHash> for Anchor {
    fn from(anchor: DomainMerkleHash) -> Anchor {
        Anchor(anchor.0)
    }
}

impl Anchor {
    pub fn value(&self) -> pallas::Base {
        self.0
    }
}

impl Anchor {
    pub fn from_bytes(bytes: [u8; 32]) -> CtOption<Anchor> {
        pallas::Base::from_repr(bytes).map(Anchor)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[derive(Debug)]
pub struct MerklePath {
    position: u32,
    auth_path: [DomainMerkleHash; MERKLE_DEPTH],
}

impl MerklePath {
    pub(crate) fn dummy(mut rng: &mut impl RngCore) -> Self {
        MerklePath {
            position: rng.next_u32(),
            auth_path: gen_const_array_with_default(DomainMerkleHash::empty_leaf(), |_| {
                DomainMerkleHash(pallas::Base::random(&mut rng))
            }),
        }
    }

    pub fn new(position: u32, auth_path: [pallas::Base; MERKLE_DEPTH]) -> Self {
        Self::from_parts(
            position,
            gen_const_array_with_default(DomainMerkleHash::empty_leaf(), |i| {
                DomainMerkleHash(auth_path[i])
            }),
        )
    }

    pub fn from_parts(position: u32, auth_path: [DomainMerkleHash; MERKLE_DEPTH]) -> Self {
        Self {
            position,
            auth_path,
        }
    }

    pub fn root(&self, cmx: ExtractedCommitment) -> Anchor {
        self.auth_path
            .iter()
            .enumerate()
            .fold(DomainMerkleHash::from_cmx(&cmx), |node, (l, sibling)| {
                let l = l as u8;
                if self.position & (1 << l) == 0 {
                    DomainMerkleHash::combine(l.into(), &node, sibling)
                } else {
                    DomainMerkleHash::combine(l.into(), sibling, &node)
                }
            })
            .into()
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn auth_path(&self) -> [DomainMerkleHash; MERKLE_DEPTH] {
        self.auth_path
    }
}
