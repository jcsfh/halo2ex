// refer https://github.com/zcash/orchard/blob/main/src/value.rs

use ff::Field;
use group::{Curve, Group, GroupEncoding};
use pasta_curves::{arithmetic::CurveAffine, pallas};

use rand::RngCore;
use subtle::CtOption;

use std::convert::From;
use std::fmt::{self, Debug};
use std::iter::Sum;
use std::num::ParseIntError;
use std::ops::{Add, Div, Mul, Neg, Rem, Sub};

use bitvec::{array::BitArray, order::Lsb0, store::BitStore};
use funty::Signed;
use lazy_static::lazy_static;

#[derive(Debug)]
pub struct OverflowError;

impl fmt::Display for OverflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValueType operation overflowed")
    }
}

impl std::error::Error for OverflowError {}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ValueType<S: Signed>(S);

lazy_static! {
    static ref I128MAX: String = i128::MAX.to_string();
    static ref I64MAX: String = i64::MAX.to_string();
    static ref I32MAX: String = i32::MAX.to_string();
    static ref I16MAX: String = i16::MAX.to_string();
}

impl<S: Signed> ValueType<S> {
    pub fn from(value: S) -> Result<Self, OverflowError> {
        if Self::is_valid_range(value, false) {
            Ok(ValueType(value))
        } else {
            Err(OverflowError)
        }
    }

    pub fn value(self) -> S {
        self.0
    }

    pub fn to_i128(self) -> i128 {
        self.0.as_i128()
    }

    pub fn to_u64(self) -> Result<u64, ParseIntError> {
        self.0.to_string().parse::<u64>()
    }

    pub fn to_base(self) -> Option<pallas::Base> {
        let v = self.to_u64();
        if v.is_ok() {
            Some(pallas::Base::from(v.unwrap()))
        } else {
            None
        }
    }

    pub fn zero() -> Self {
        ValueType(S::ZERO)
    }

    pub fn from_bytes(bytes: S::Bytes) -> Self {
        ValueType(S::from_le_bytes(bytes))
    }

    pub fn to_bytes(self) -> S::Bytes {
        self.0.to_le_bytes()
    }

    pub fn to_le_bits(self) -> BitArray<Lsb0, S::Bytes>
    where
        S::Bytes: BitStore,
    {
        BitArray::<Lsb0, _>::new(self.0.to_le_bytes())
    }

    // if sum, the range must be (-u[S/2]::MAX) - (u[S/2]::MAX)
    // if not sum, the range must be 0 - u[S/2]::MAX
    pub fn is_valid_range(v: S, sum: bool) -> bool {
        if sum {
            v >= S::MIN && v <= S::MAX
        } else {
            v >= S::ZERO && v < (S::ONE << (S::BITS / 2))
        }
    }
}

impl<S: Signed> Neg for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn neg(self) -> Self::Output {
        self.0
            .checked_neg()
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<S: Signed> Add for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self::Output {
        self.0
            .checked_add(rhs.0)
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<S: Signed> Sub for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self.0
            .checked_sub(rhs.0)
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<S: Signed> Mul for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn mul(self, rhs: Self) -> Self::Output {
        self.0
            .checked_mul(rhs.0)
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<S: Signed> Div for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self.0
            .checked_div(rhs.0)
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<S: Signed> Rem for ValueType<S> {
    type Output = Option<ValueType<S>>;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn rem(self, rhs: Self) -> Self::Output {
        self.0
            .checked_rem(rhs.0)
            .filter(|v| Self::is_valid_range(*v, true))
            .map(|v| ValueType(v))
    }
}

impl<'a, S: Signed> Sum<&'a ValueType<S>> for Result<ValueType<S>, OverflowError> {
    fn sum<I: Iterator<Item = &'a ValueType<S>>>(iter: I) -> Self {
        iter.fold(Ok(ValueType(S::ZERO)), |acc, v| {
            (acc? + *v).ok_or(OverflowError)
        })
    }
}

impl<S: Signed> Sum<ValueType<S>> for Result<ValueType<S>, OverflowError> {
    fn sum<I: Iterator<Item = ValueType<S>>>(iter: I) -> Self {
        iter.fold(Ok(ValueType(S::ZERO)), |acc, v| {
            (acc? + v).ok_or(OverflowError)
        })
    }
}

#[derive(Clone, Debug)]
pub struct ValueCommitTrapdoor(pallas::Scalar);

impl Add<&ValueCommitTrapdoor> for ValueCommitTrapdoor {
    type Output = ValueCommitTrapdoor;

    fn add(self, rhs: &Self) -> Self::Output {
        ValueCommitTrapdoor(self.0 + rhs.0)
    }
}

impl<'a> Sum<&'a ValueCommitTrapdoor> for ValueCommitTrapdoor {
    fn sum<I: Iterator<Item = &'a ValueCommitTrapdoor>>(iter: I) -> Self {
        iter.fold(ValueCommitTrapdoor::zero(), |acc, cv| acc + cv)
    }
}

impl ValueCommitTrapdoor {
    /// Generates a new value commitment trapdoor.
    pub fn random(rng: impl RngCore) -> Self {
        ValueCommitTrapdoor(pallas::Scalar::random(rng))
    }

    /// Returns the zero trapdoor, which provides no blinding.
    pub fn zero() -> Self {
        ValueCommitTrapdoor(pallas::Scalar::zero())
    }

    pub fn value(&self) -> pallas::Scalar {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct ValueCommitment(pallas::Point);

impl From<pallas::Point> for ValueCommitment {
    fn from(p: pallas::Point) -> Self {
        ValueCommitment(p)
    }
}

impl Add<&ValueCommitment> for ValueCommitment {
    type Output = ValueCommitment;

    fn add(self, rhs: &Self) -> Self::Output {
        ValueCommitment(self.0 + rhs.0)
    }
}

impl Sub for ValueCommitment {
    type Output = ValueCommitment;

    fn sub(self, rhs: Self) -> Self::Output {
        ValueCommitment(self.0 - rhs.0)
    }
}

impl Sum for ValueCommitment {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(ValueCommitment(pallas::Point::identity()), |acc, cv| {
            acc + &cv
        })
    }
}

impl<'a> Sum<&'a ValueCommitment> for ValueCommitment {
    fn sum<I: Iterator<Item = &'a ValueCommitment>>(iter: I) -> Self {
        iter.fold(ValueCommitment(pallas::Point::identity()), |acc, cv| {
            acc + cv
        })
    }
}

impl ValueCommitment {
    /// Deserialize a value commitment from its byte representation
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<ValueCommitment> {
        pallas::Point::from_bytes(bytes).map(ValueCommitment)
    }

    pub fn value(&self) -> pallas::Point {
        self.0
    }

    /// Serialize this value commitment to its canonical byte representation.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// x-coordinate of this value commitment.
    pub fn x(&self) -> pallas::Base {
        if self.0 == pallas::Point::identity() {
            pallas::Base::zero()
        } else {
            *self.0.to_affine().coordinates().unwrap().x()
        }
    }

    /// y-coordinate of this value commitment.
    pub fn y(&self) -> pallas::Base {
        if self.0 == pallas::Point::identity() {
            pallas::Base::zero()
        } else {
            *self.0.to_affine().coordinates().unwrap().y()
        }
    }
}
