#![allow(dead_code)]

use std::ops::Deref;

use group::Group;
use group::GroupEncoding;
use pasta_curves::pallas;
use rand::RngCore;
use subtle::{ConditionallySelectable, CtOption};

/// A Pallas point that is guaranteed to not be the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonIdentityPallasPoint(pallas::Point);

impl Default for NonIdentityPallasPoint {
    fn default() -> Self {
        NonIdentityPallasPoint(pallas::Point::generator())
    }
}

impl ConditionallySelectable for NonIdentityPallasPoint {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        NonIdentityPallasPoint(pallas::Point::conditional_select(&a.0, &b.0, choice))
    }
}

impl NonIdentityPallasPoint {
    pub(crate) fn dummy(rng: &mut impl RngCore) -> Self {
        Self(pallas::Point::random(rng))
    }

    pub fn value(&self) -> pallas::Point {
        self.0
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Point::from_bytes(bytes)
            .and_then(|p| CtOption::new(NonIdentityPallasPoint(p), !p.is_identity()))
    }

    pub fn mul(&self, r: &pallas::Scalar) -> NonIdentityPallasPoint {
        let mut wnaf = group::Wnaf::new();
        NonIdentityPallasPoint(wnaf.scalar(r).base(self.0))
    }
}

impl Deref for NonIdentityPallasPoint {
    type Target = pallas::Point;

    fn deref(&self) -> &pallas::Point {
        &self.0
    }
}
