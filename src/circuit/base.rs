use pasta_curves::{pallas, vesta};

use halo2_proofs::{
    circuit::AssignedCell,
    plonk::{Advice, Column, Instance as InstanceColumn, Selector},
};

use halo2_gadgets::{
    ecc::chip::EccConfig,
    poseidon::Pow5Config as PoseidonConfig,
    sinsemilla::{chip::SinsemillaConfig, merkle::chip::MerkleConfig},
};

use funty::Signed;
use std::collections::BTreeMap;
use std::marker::PhantomData;

use crate::domains::*;
use crate::sinsemilla::config::*;
use crate::types::*;

pub trait InstanceOrder {
    fn get_instance_order() -> Vec<String>;
}

pub trait ICConfig: InstanceOrder {
    type Value: Signed;

    fn get_ic_configs() -> (Vec<GateConfig>, Vec<Vec<AlgoConfig>>);

    fn get_commit_gate_configs(domain: &String) -> Option<Vec<GateConfig>>; //cell_name, attr_name, cell_type, col_type, col, row, width
    fn get_commit_configs(
    ) -> Option<Vec<(bool, String, (String, usize), Vec<(String, String)>, String)>>; // (is_short_commit, commit_name, (domain_name, num_window), input name list(name, type), random_name)
}

pub(crate) type CellValues = BTreeMap<
    String,
    (
        Option<AssignedCell<pallas::Base, pallas::Base>>,
        Option<AssignedCell<pallas::Base, pallas::Base>>,
    ),
>;

#[derive(Clone, Debug)]
pub struct ConfigData {
    pub(crate) gates: Vec<GateInfo>,
    pub(crate) algos: Vec<Vec<Algo>>,
    pub(crate) primary: Column<InstanceColumn>,
    pub(crate) instance_info: BTreeMap<String, usize>, // offset
    pub(crate) qs: Vec<Selector>,
    pub(crate) advices: [Column<Advice>; 10],
    pub(crate) ecc_config: EccConfig<DomainFixedBases>,
    pub(crate) poseidon_config: PoseidonConfig<pallas::Base, 3, 2>,
    pub(crate) merkle_config_1: MerkleConfig<BaseHashDomains, HashDomainsType, DomainFixedBases>,
    pub(crate) merkle_config_2: MerkleConfig<BaseHashDomains, HashDomainsType, DomainFixedBases>,
    pub(crate) sinsemilla_config_1:
        SinsemillaConfig<BaseHashDomains, HashDomainsType, DomainFixedBases>,
    pub(crate) commit_configs: Option<
        Vec<(
            String,
            (
                bool,
                CommitConfig,
                HashDomainsType,
                Vec<(String, String)>,
                String,
            ),
        )>,
    >, // commit_name, (config, input name list(name, type), random_name)
}

#[derive(Clone, Debug, Default)]
pub struct Instance<T: InstanceOrder> {
    pub enables: BTreeMap<String, bool>,
    pub fields: BTreeMap<String, pallas::Base>,
    pub _nothing: PhantomData<T>,
}

impl<T: InstanceOrder> Instance<T> {
    pub(crate) fn to_instances(&self) -> Box<BTreeMap<String, vesta::Scalar>> {
        let instances = std::iter::empty()
            .chain(
                self.enables
                    .iter()
                    .map(|(name, v)| (name.clone(), vesta::Scalar::from(u64::from(*v))))
                    .collect::<BTreeMap<_, _>>(),
            )
            .chain(
                self.fields
                    .iter()
                    .map(|(name, v)| (name.clone(), *v))
                    .collect::<BTreeMap<_, _>>(),
            )
            .collect();

        Box::new(instances)
    }

    pub(crate) fn instances_to_halo2_instance(
        instances: &Box<BTreeMap<String, vesta::Scalar>>,
    ) -> Vec<Vec<vesta::Scalar>> {
        let i = T::get_instance_order()
            .iter()
            .map(|name| {
                debug_assert!(
                    instances.contains_key(name),
                    "instances_to_halo2_instance: {} not in instances",
                    name
                );
                *instances.get(name).unwrap_or(&vesta::Scalar::default())
            })
            .collect();
        vec![i]
    }

    pub fn to_halo2_instance(&self) -> Vec<Vec<vesta::Scalar>> {
        Self::instances_to_halo2_instance(&self.to_instances())
    }
}
