// from https://github.com/zcash/orchard/blob/main/src/constants/util.rs

use ff::PrimeField;
use group::Curve;
use halo2_gadgets::{
    primitives::{poseidon, sinsemilla::K},
    utilities::i2lebsp,
    utilities::lebs2ip,
};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use pasta_curves::pallas;
use subtle::CtOption;

/// Takes in an FnMut closure and returns a constant-length array with elements of
/// type `Output`.
pub fn gen_const_array<Output: Copy + Default, const LEN: usize>(
    closure: impl FnMut(usize) -> Output,
) -> [Output; LEN] {
    gen_const_array_with_default(Default::default(), closure)
}

pub fn gen_const_array_with_default<Output: Copy, const LEN: usize>(
    default_value: Output,
    mut closure: impl FnMut(usize) -> Output,
) -> [Output; LEN] {
    let mut ret: [Output; LEN] = [default_value; LEN];
    for (bit, val) in ret.iter_mut().zip((0..LEN).map(|idx| closure(idx))) {
        *bit = val;
    }
    ret
}

// public methods
pub fn i2lebsp_k(int: usize) -> [bool; K] {
    assert!(int < (1 << K));
    i2lebsp(int as u64)
}

pub fn extract_p(point: &pallas::Point) -> pallas::Base {
    point
        .to_affine()
        .coordinates()
        .map(|c| *c.x())
        .unwrap_or_else(pallas::Base::zero)
}

pub fn lebs2ip_field<F: PrimeField, const L: usize>(bits: &[bool; L]) -> F {
    F::from(lebs2ip::<L>(bits))
}

pub fn extract_p_bottom(point: CtOption<pallas::Point>) -> CtOption<pallas::Base> {
    point.map(|p| extract_p(&p))
}

pub fn to_scalar(x: [u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_bytes_wide(&x)
}

pub fn to_base(x: [u8; 64]) -> pallas::Base {
    pallas::Base::from_bytes_wide(&x)
}

pub fn mod_r_p(x: pallas::Base) -> pallas::Scalar {
    pallas::Scalar::from_repr(x.to_repr()).unwrap()
}

// N is supposed to be 2, other number might cause lower performance
pub fn poseidon_hash<const N: usize>(inputs: &[pallas::Base; N]) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<N>, 3, 2>::init()
        .hash(*inputs)
}
