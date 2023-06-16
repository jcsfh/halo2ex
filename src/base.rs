#![allow(unused_macros)]

use halo2_proofs::arithmetic::CurveExt;
use pasta_curves::{arithmetic::CurveAffine, group::ff::PrimeField, group::Curve, pallas};

use halo2_gadgets::{
    ecc::chip::{find_zs_and_us, H},
    primitives::sinsemilla::{CommitDomain, HashDomain},
};

use super::types::*;

pub fn string_to_static_str(s: &String) -> &'static str {
    Box::leak(s.clone().into_boxed_str())
}

macro_rules! assert_error {
    ($c:expr, $e:expr, $d:expr) => {
        debug_assert!($c, "{}", $d);
        if !$c {
            println!("!assert failed at {}:{}", std::file!(), std::line!());
            return Err($e);
        }
    };
}

macro_rules! assert_eq_error {
    ($c1:expr, $c2:expr, $e:expr, $d:expr) => {
        debug_assert_eq!($c1, $c2, "{}", $d);
        if $c1 != $c2 {
            println!(
                "!assert_eq failed: left: {:?}\nright: {:?}\nat {}:{}",
                $c1,
                $c2,
                std::file!(),
                std::line!()
            );
            return Err($e);
        }
    };
}

// panic is just for passing complilation
macro_rules! assert_error_and_panic {
    ($c:expr, $e:expr, $d:expr) => {
        assert_error!($c, $e, $d);
        panic!();
    };
}

macro_rules! assert_synthesize_error {
    ($c:expr, $d:expr) => {
        assert_error!($c, plonk::Error::Synthesis, $d);
    };
}

macro_rules! assert_eq_synthesize_error {
    ($c1:expr, $c2:expr, $d:expr) => {
        assert_eq_error!($c1, $c2, plonk::Error::Synthesis, $d);
    };
}

macro_rules! assert_synthesize_error_and_panic {
    ($c:expr, $d:expr) => {
        assert_error_and_panic!($c, plonk::Error::Synthesis, $d);
    };
}

#[allow(non_snake_case)]
pub fn Q_HashDomain(domain: &str) -> pallas::Affine {
    let point = HashDomain::new(domain).Q();
    point.to_affine()
}

#[allow(non_snake_case)]
pub fn Q_CommitDomain(domain: &str) -> pallas::Affine {
    let point = CommitDomain::new(domain).Q();
    point.to_affine()
}

#[allow(non_snake_case)]
pub fn R(domain: &str) -> pallas::Affine {
    let domain = CommitDomain::new(domain);
    let point = domain.R();
    point.to_affine()
}

pub fn affine_to_bytes(a: &pallas::Affine) -> TGenerator {
    let r = a.coordinates().unwrap();
    (r.x().to_repr(), r.y().to_repr())
}

pub fn create_generator_q_hash_domain(domain: &str) -> TGenerator {
    let point = Q_HashDomain(domain);
    affine_to_bytes(&point)
}

pub fn create_generator_q_commit_domain(domain: &str) -> TGenerator {
    let point = Q_CommitDomain(domain);
    affine_to_bytes(&point)
}

pub fn create_generator_r(domain: &str) -> TGenerator {
    let point = R(domain);
    affine_to_bytes(&point)
}

pub fn generator_q_hash_domain(domain: &str) -> pallas::Affine {
    let value = create_generator_q_hash_domain(domain);

    pallas::Affine::from_xy(
        pallas::Base::from_repr(value.0).unwrap(),
        pallas::Base::from_repr(value.1).unwrap(),
    )
    .unwrap()
}

pub fn generator_q_commit_domain(domain: &str) -> pallas::Affine {
    let value = create_generator_q_commit_domain(domain);

    pallas::Affine::from_xy(
        pallas::Base::from_repr(value.0).unwrap(),
        pallas::Base::from_repr(value.1).unwrap(),
    )
    .unwrap()
}

pub fn generator_r(domain: &str) -> pallas::Affine {
    let value = create_generator_r(domain);

    pallas::Affine::from_xy(
        pallas::Base::from_repr(value.0).unwrap(),
        pallas::Base::from_repr(value.1).unwrap(),
    )
    .unwrap()
}

pub fn get_zs_and_us<C: CurveAffine>(base: C, num_windows: usize) -> Option<TVecZsUs<C>> {
    find_zs_and_us(base, num_windows)
}

pub fn convert_zs_us(zs_and_us: TVecZsUs<pallas::Affine>) -> TZsUs {
    let zs_us: (Vec<u64>, Vec<[pallas::Base; H]>) = zs_and_us.into_iter().unzip();
    let us = zs_us
        .1
        .iter()
        .map(|us| {
            [
                us[0].to_repr(),
                us[1].to_repr(),
                us[2].to_repr(),
                us[3].to_repr(),
                us[4].to_repr(),
                us[5].to_repr(),
                us[6].to_repr(),
                us[7].to_repr(),
            ]
        })
        .collect::<Vec<_>>();
    (zs_us.0, us)
}

pub fn generate_zs_us(base: pallas::Affine, num_windows: usize) -> TZsUs {
    convert_zs_us(find_zs_and_us(base, num_windows).unwrap())
}

pub fn generate_q_hash_domain(domain: &str) -> TGenerator {
    affine_to_bytes(&generator_q_hash_domain(domain))
}

pub fn generate_q_commit_domain(domain: &str) -> TGenerator {
    affine_to_bytes(&generator_q_commit_domain(domain))
}

pub fn generate_r(domain: &str) -> TGenerator {
    affine_to_bytes(&generator_r(domain))
}

pub fn generate_hash_point(domain: &str, t: &[u8]) -> TGenerator {
    let hasher = pallas::Point::hash_to_curve(domain);
    let point = hasher(t);
    affine_to_bytes(&point.to_affine())
}

pub fn point_to_affine(p: &TGenerator) -> pallas::Affine {
    pallas::Affine::from_xy(
        pallas::Base::from_repr(p.0).unwrap(),
        pallas::Base::from_repr(p.1).unwrap(),
    )
    .unwrap()
}

pub fn print_sinsemilla_commit_domains(name: &str, num_window: usize) {
    let (x, y) = generate_q_commit_domain(&name);
    println!("===> Q Commit Domain:");
    println!("{:?}\n{:?}", x, y);

    let basepoint = generator_r(&name);
    let (x, y) = affine_to_bytes(&basepoint);
    println!("===> R:");
    println!("{:?}\n{:?}", x, y);

    let (zs, us) = generate_zs_us(basepoint, num_window);
    println!("===> ZS and US:");
    println!("{:?}", zs);
    println!("{:?}", us);
    println!("----------------------------");
}

//k, G, r, v
pub fn print_hash_point_domains(name: &str, num_window: usize, h: &[u8; 1]) {
    let p = generate_hash_point(&name, h);
    println!("===> Hash Point:");
    println!("{:?}\n{:?}", p.0, p.1,);

    println!("===> ZS and US:");
    let (zs, us) = generate_zs_us(point_to_affine(&p), num_window);
    println!("{:?}", zs);
    println!("{:?}", us);
}

pub fn print_q_hash_domain(name: &str) {
    let (x, y) = generate_q_hash_domain(&name);
    println!("===> Q Hash Domain:");
    println!("{:?}\n{:?}", x, y,);
}
