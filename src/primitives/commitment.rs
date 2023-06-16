// refer https://github.com/zcash/orchard/blob/main/src/note/commitment.rs

#![allow(dead_code)]

use bitvec::{array::BitArray, order::Lsb0, store::BitStore};
use group::ff::{PrimeField, PrimeFieldBits};
use group::Group;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::{ConstantTimeEq, CtOption};

use halo2_gadgets::primitives::sinsemilla;

use funty::Signed;

use super::utils::*;
use super::value::*;
use crate::consts::*;

#[derive(Clone, Debug)]
pub struct CommitTrapdoor(pub(super) pallas::Scalar);

impl CommitTrapdoor {
    pub fn value(&self) -> pallas::Scalar {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct Commitment(pub pallas::Point);

impl AsRef<pallas::Point> for Commitment {
    fn as_ref(&self) -> &pallas::Point {
        &self.0
    }
}

impl Commitment {
    pub(crate) fn dummy(rng: &mut impl RngCore) -> Self {
        Self(pallas::Point::random(rng))
    }

    pub fn value(&self) -> pallas::Point {
        self.0
    }

    pub fn derive<S: Signed>(
        domain: &str,
        bits: &Vec<[u8; 32]>,
        values: &Vec<ValueType<S>>,
        points: &Vec<pallas::Base>,
        rcm: CommitTrapdoor,
    ) -> CtOption<Self>
    where
        S::Bytes: BitStore,
    {
        let mut chains = Vec::new();
        for bit in bits {
            chains.extend(BitArray::<Lsb0, _>::new(*bit).iter().by_val());
        }
        for value in values {
            chains.extend(value.to_le_bits().iter().by_val());
        }
        for point in points {
            chains.extend(point.to_le_bits().iter().by_val().take(FILED_SIZE));
        }

        let domain = sinsemilla::CommitDomain::new(domain);
        domain.commit(chains.into_iter(), &rcm.0).map(Commitment)
    }
}

impl From<Commitment> for ExtractedCommitment {
    fn from(cm: Commitment) -> Self {
        ExtractedCommitment(extract_p(&cm.0))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ExtractedCommitment(pub(super) pallas::Base);

impl ExtractedCommitment {
    pub fn value(&self) -> pallas::Base {
        self.0
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(ExtractedCommitment)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl From<&ExtractedCommitment> for [u8; 32] {
    fn from(cmx: &ExtractedCommitment) -> Self {
        cmx.to_bytes()
    }
}

impl ConstantTimeEq for ExtractedCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ExtractedCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ExtractedCommitment {}
