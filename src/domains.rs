use ff::PrimeFieldBits;
use pasta_curves::{arithmetic::CurveAffine, group::ff::PrimeField, pallas};

use halo2_gadgets::{
    ecc::{
        chip::{BaseFieldElem, FixedPoint, FullScalar, ShortScalar},
        FixedPoints,
    },
    primitives::sinsemilla::CommitDomain,
    sinsemilla::{CommitDomains, HashDomains},
    utilities::bitrange_subset,
};

use crate::base;
use crate::consts::*;
use crate::global;
use crate::types::*;

pub mod global_domain {
    use super::*;
    use lazy_static::lazy_static;
    use std::sync::Mutex;

    lazy_static! {
        static ref COMMIT_DOMAINS: Mutex<Vec<HashDomainsType>> = Mutex::new(Vec::new());
    }

    pub fn add_commit_domain(domain_name: &str, num_windows: usize) {
        let commit_domain = HashDomainsType {
            domain: domain_name.to_string(),
            num_windows: num_windows,
            is_hash_domain: false,
        };
        COMMIT_DOMAINS.lock().unwrap().insert(0, commit_domain);
    }

    pub(crate) fn get_next_commit_domain() -> Option<HashDomainsType> {
        COMMIT_DOMAINS.lock().unwrap().pop()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct BaseHashDomains {
    pub domain: String,
    pub(crate) is_hash_domain: bool,
}

#[allow(non_snake_case)]
impl HashDomains<pallas::Affine> for BaseHashDomains {
    fn Q(&self) -> pallas::Affine {
        let generator = global::get_generator_q(&self.domain);
        if generator.is_none() {
            if self.is_hash_domain {
                base::generator_q_hash_domain(&self.domain)
            } else {
                base::generator_q_commit_domain(&self.domain)
            }
        } else {
            let generator = generator.unwrap();
            pallas::Affine::from_xy(
                pallas::Base::from_repr(generator.0).unwrap(),
                pallas::Base::from_repr(generator.1).unwrap(),
            )
            .unwrap()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DomainFullWidth {
    pub domain: String,
    pub num_windows: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DomainBaseField {
    pub domain: String,
    pub num_windows: usize,
}
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct DomainShort {
    pub domain: String,
    pub num_windows_short: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct DomainFixedBases;

impl FixedPoints<pallas::Affine> for DomainFixedBases {
    type FullScalar = DomainFullWidth;
    type Base = DomainBaseField;
    type ShortScalar = DomainShort;
}

impl FixedPoint<pallas::Affine> for DomainFullWidth {
    type ScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        global::generator(&self.domain)
    }

    fn u(&self) -> TUs {
        global::u(&self.domain, self.num_windows)
    }

    fn z(&self) -> TZs {
        global::z(&self.domain, self.num_windows)
    }
}

impl FixedPoint<pallas::Affine> for DomainBaseField {
    type ScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        global::generator(&self.domain)
    }

    fn u(&self) -> TUs {
        global::u(&self.domain, self.num_windows)
    }

    fn z(&self) -> TZs {
        global::z(&self.domain, self.num_windows)
    }
}

impl FixedPoint<pallas::Affine> for DomainShort {
    type ScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        global::generator(&self.domain)
    }

    fn u(&self) -> TUs {
        global::u_short(&self.domain, self.num_windows_short)
    }

    fn z(&self) -> TZs {
        global::z_short(&self.domain, self.num_windows_short)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct HashDomainsType {
    pub domain: String,
    pub num_windows: usize,
    pub is_hash_domain: bool,
}

impl CommitDomains<pallas::Affine, DomainFixedBases, BaseHashDomains> for HashDomainsType {
    fn r(&self) -> DomainFullWidth {
        DomainFullWidth {
            domain: self.domain.clone(),
            num_windows: self.num_windows,
        }
    }

    fn hash_domain(&self) -> BaseHashDomains {
        BaseHashDomains {
            domain: self.domain.clone(),
            is_hash_domain: self.is_hash_domain,
        }
    }
}

pub fn compute_commit_value(
    is_short_commit: bool,
    commit_domain_name: &str,
    input_r: &pallas::Scalar,
    inputs: &CommitInputs,
) -> CommitResult {
    let mut bits = Vec::new();

    let lsb = |y_lsb: pallas::Base| y_lsb == pallas::Base::one();
    for (_name, width, x, y) in inputs {
        bits.extend(
            x.unwrap()
                .to_le_bits()
                .iter()
                .by_val()
                .take(std::cmp::min(*width, FILED_SIZE)),
        );

        if y.is_some() {
            debug_assert!(
                !is_short_commit,
                "[Sinsemilla] [{}] must be full commit",
                commit_domain_name
            );

            let y = bitrange_subset(&y.unwrap(), 0..1);
            bits.push(lsb(y));
        }
    }

    let domain = CommitDomain::new(commit_domain_name);
    if is_short_commit {
        let x = domain
            .short_commit(bits.clone().into_iter(), input_r)
            .unwrap();
        CommitResult::X(Some(x))
    } else {
        let p = domain.commit(bits.into_iter(), &input_r).unwrap();
        CommitResult::Point(Some(p))
    }
}
