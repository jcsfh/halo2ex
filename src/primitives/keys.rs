#![allow(dead_code)]

use pasta_curves::pallas;

use group::{Group, GroupEncoding};
use rand::RngCore;
use std::convert::TryInto;
use std::marker::PhantomData;

use crate::global;

pub trait Randomizer {
    fn randomize(
        base: &pallas::Point,
        randomizer: &pallas::Scalar,
        domain_name: &str,
        h: &[u8; 1],
    ) -> pallas::Point;
}

#[derive(Debug, Clone)]
pub struct ValidatingKey<T: Randomizer> {
    pub bytes: [u8; 32],
    pub point: pallas::Point,
    _nothing: PhantomData<T>,
}

impl<T: Randomizer> From<ValidatingKey<T>> for [u8; 32] {
    fn from(key: ValidatingKey<T>) -> [u8; 32] {
        key.bytes
    }
}

impl<T: Randomizer> From<&[u8; 32]> for ValidatingKey<T> {
    fn from(bytes: &[u8; 32]) -> Self {
        Self {
            bytes: bytes.clone(),
            point: pallas::Point::from_bytes(bytes).unwrap(),
            _nothing: Default::default(),
        }
    }
}

impl<T: Randomizer> From<&pallas::Point> for ValidatingKey<T> {
    fn from(point: &pallas::Point) -> ValidatingKey<T> {
        Self {
            bytes: point.to_bytes().as_ref().try_into().unwrap(),
            point: point.clone(),
            _nothing: Default::default(),
        }
    }
}

impl<T: Randomizer> From<&ValidatingKey<T>> for pallas::Point {
    fn from(key: &ValidatingKey<T>) -> pallas::Point {
        key.point
    }
}

impl<T: Randomizer> ValidatingKey<T> {
    pub fn basepoint(domain_name: &str, h: &[u8; 1]) -> pallas::Point {
        pallas::Point::from_bytes(&global::get_base_point(domain_name, h)).unwrap()
    }

    pub fn randomize(&self, randomizer: &pallas::Scalar, domain_name: &str, h: &[u8; 1]) -> Self {
        Self::from(&T::randomize(&self.point, randomizer, domain_name, h))
    }

    pub(crate) fn dummy(rng: &mut impl RngCore) -> ValidatingKey<T> {
        ValidatingKey::from(&pallas::Point::random(rng))
    }
}
