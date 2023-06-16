#![cfg_attr(
    debug_assertions,
    allow(
        dead_code,
        unused_imports,
        unused_variables,
        unused_mut,
        unused_macros,
        non_camel_case_types
    )
)]

// refer https://github.com/zcash/orchard/blob/main/src/note/nullifier.rs

use group::{ff::PrimeField, Group};
use pasta_curves::pallas;
use rand::RngCore;
use subtle::CtOption;

use super::utils::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Nullifier(pub pallas::Base);

impl Nullifier {
    pub(crate) fn dummy(rng: &mut impl RngCore) -> Self {
        Nullifier(extract_p(&pallas::Point::random(rng)))
    }

    pub fn value(&self) -> pallas::Base {
        self.0
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(Nullifier)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}
