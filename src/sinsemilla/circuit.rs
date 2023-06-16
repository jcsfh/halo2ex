#![allow(unused_imports)]
use group::Curve;

use pasta_curves::{
    group::ff::{Field, PrimeField},
    pallas,
};

use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    dev::{MockProver, VerifyFailure},
    plonk::{self, Circuit, ConstraintSystem, Error},
};

use halo2_gadgets::{
    ecc::{
        chip::{EccChip, EccConfig},
        NonIdentityPoint,
    },
    sinsemilla::chip::SinsemillaChip,
    utilities::{lookup_range_check::LookupRangeCheckConfig, UtilitiesInstructions},
};

use std::{collections::BTreeMap, convert::TryInto, marker::PhantomData};

use super::config::*;
use crate::base;
use crate::domains::*;
use crate::halo2api;
use crate::types::*;

type SinsemillaConfigType = (CommitConfig, EccConfig<DomainFixedBases>, Vec<GateInfo>);
type CommitInputMap = BTreeMap<String, ((Option<pallas::Base>, usize), Option<pallas::Base>)>;
pub(crate) type CommitInputVec = Vec<(String, Option<pallas::Base>, Option<pallas::Base>)>;

pub trait ISinsemillaCircuit {
    fn get_commit_gate_config(domain: &String) -> Vec<GateInfo>;
}

#[derive(Clone, Debug)]
pub struct SinsemillaCircuit<T: ISinsemillaCircuit> {
    pub is_short_commit: bool,
    pub commit_domain_name: String,
    pub inputs: CommitInputVec,
    pub input_r: Option<pallas::Scalar>,
    pub _nothing: PhantomData<T>,
}

impl<T: ISinsemillaCircuit> Default for SinsemillaCircuit<T> {
    fn default() -> Self {
        Self {
            is_short_commit: true,
            commit_domain_name: Default::default(),
            inputs: Default::default(),
            input_r: Default::default(),
            _nothing: Default::default(),
        }
    }
}

impl<T: ISinsemillaCircuit> UtilitiesInstructions<pallas::Base> for SinsemillaCircuit<T> {
    type Var = AssignedCell<pallas::Base, pallas::Base>;
}

impl<T: ISinsemillaCircuit> SinsemillaCircuit<T> {
    pub fn new(
        is_short_commit: bool,
        commit_domain_name: &str,
        inputs: &CommitInputVec,
        input_r: Option<pallas::Scalar>,
        gates: &Vec<GateInfo>,
    ) -> Self {
        debug_assert!(
            inputs.len() == 0 || inputs[0].1.is_none() || input_r.is_some(),
            "[Sinsemilla] input random is none, but not in without_witnesses mode"
        );
        let verify_input_num = |gates: &Vec<GateInfo>| {
            let input_num = gates.iter().fold(0, |n, gate| {
                if CellType::is_input_cell(gate.cells[0].celltype) {
                    n + 1
                } else {
                    n
                }
            });
            debug_assert_eq!(
                input_num,
                inputs.len(),
                "[Sinsemilla] input number[{}] does not match the gate config number[{}]",
                input_num,
                inputs.len()
            )
        };
        if gates.len() == 0 {
            verify_input_num(&T::get_commit_gate_config(&commit_domain_name.to_string()));
        } else {
            verify_input_num(gates);
        }

        Self {
            is_short_commit: is_short_commit,
            commit_domain_name: commit_domain_name.to_string(),
            inputs: inputs.clone(),
            input_r: input_r,
            _nothing: Default::default(),
        }
    }

    pub(crate) fn do_configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        commit_domain: HashDomainsType,
        gates: &Vec<GateInfo>,
    ) -> SinsemillaConfigType {
        let advices = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let lagrange_coeffs = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);
        let sinsemilla_config =
            SinsemillaChip::<BaseHashDomains, HashDomainsType, DomainFixedBases>::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[2],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );

        let commit_config =
            CommitConfig::configure(meta, advices, sinsemilla_config, commit_domain, gates);

        let ecc_config =
            EccChip::<DomainFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        (commit_config, ecc_config, gates.clone())
    }

    pub(crate) fn do_synthesize(
        &self,
        config: &SinsemillaConfigType,
        ecc_chip: &EccChip<DomainFixedBases>,
        layouter: &mut impl Layouter<pallas::Base>,
        input_map: &mut InputConfigMap,
        is_with_witnesses: bool,
    ) -> Result<PointResult, Error> {
        assert_synthesize_error!(
            self.input_r.is_none() || self.inputs.len() > 0,
            format!("[Sinsemilla::do_synthesize] no any input")
        );
        let is_with_witnesses =
            is_with_witnesses && self.input_r.is_some() && self.inputs[0].1.is_some();
        let mut _debug_info = if is_with_witnesses && cfg!(feature = "debug") {
            Some(BTreeMap::new())
        } else {
            None
        };

        let (commit_config, _ecc_config, gates) = config;

        #[cfg(feature = "debug")]
        let is_independent = input_map.len() == 0;

        let mut inputs = self
            .inputs
            .iter()
            .map(|(name, x, y_lsb)| (name.clone(), ((x.clone(), 0), y_lsb.clone())))
            .collect::<CommitInputMap>();

        let sinsemilla_chip = SinsemillaChip::construct(commit_config.sinsemilla_config.clone());

        let mut desc;
        for gate in gates {
            let input_cell = &gate.cells[0];
            desc = format!("[Sinsemilla] witness ({})", input_cell.name);

            if inputs.contains_key(&gate.cells[0].name) {
                let value = inputs.get_mut(&gate.cells[0].name).unwrap();
                (*value).0 .1 = gate.cells[0].width;
            }

            if CellType::is_input_cell(input_cell.celltype) {
                let ((x, _width), y_lsb) = inputs.get(&input_cell.name).unwrap();
                let values = input_map.get_mut(&input_cell.name);
                if values.is_some() {
                    values.unwrap().2 = *_width;
                } else {
                    if input_cell.celltype == CellType::YInput {
                        let point = {
                            let p = y_lsb.map(|y_lsb| {
                                // y-coordinate appended
                                let mut y = (x.unwrap().square() * x.unwrap()
                                    + pallas::Affine::b())
                                .sqrt()
                                .unwrap();
                                if bool::from(y.is_odd() ^ y_lsb.is_odd()) {
                                    y = -y;
                                }
                                pallas::Affine::from_xy(x.unwrap(), y).unwrap()
                            });

                            NonIdentityPoint::new(
                                ecc_chip.clone(),
                                layouter.namespace(|| base::string_to_static_str(&desc)),
                                p,
                            )?
                        };

                        let ecc_point = point.inner();
                        input_map.insert(
                            input_cell.name.clone(),
                            (Some(ecc_point.clone().x()), Some(ecc_point.y()), *_width),
                        );
                    } else {
                        let x_value = halo2api::load_private(
                            self,
                            layouter,
                            &desc,
                            &commit_config.advices,
                            0,
                            x,
                            (&mut _debug_info, &input_cell.name),
                        )?;

                        input_map.insert(input_cell.name.clone(), (Some(x_value), None, *_width));
                    }
                }
            }
        }

        desc = format!(
            "[Sinsemilla] Hash Commit pieces ({})",
            self.commit_domain_name
        );
        let result = commit_config.assign_region(
            layouter.namespace(|| desc),
            sinsemilla_chip.clone(),
            ecc_chip.clone(),
            &input_map,
            self.input_r,
            self.is_short_commit,
            is_with_witnesses,
            &mut _debug_info,
        )?;

        #[cfg(feature = "debug")]
        if is_with_witnesses && is_independent {
            // for test
            let inputs: Vec<_> = self
                .inputs
                .iter()
                .map(|(name, x, y)| (name.clone(), input_map[name].2, x.clone(), y.clone()))
                .collect();

            if self.is_short_commit {
                let expected_result = compute_commit_value(
                    true,
                    &self.commit_domain_name,
                    &self.input_r.unwrap(),
                    &inputs,
                );

                match result {
                    PointResult::X(ref x) => match expected_result {
                        CommitResult::X(Some(expected_x)) => {
                            debug_assert_eq!(
                                &expected_x,
                                (*x).as_ref().unwrap().inner().value().unwrap()
                            );
                        }
                        _ => {}
                    },
                    _ => {}
                };
            } else {
                let expected_result = compute_commit_value(
                    false,
                    &self.commit_domain_name,
                    &self.input_r.unwrap(),
                    &inputs,
                );

                match result {
                    PointResult::Point(ref point) => match expected_result {
                        CommitResult::Point(Some(p)) => {
                            let expected_cm = NonIdentityPoint::new(
                                ecc_chip.clone(),
                                layouter.namespace(|| "[Sinsemilla] witness cm"),
                                Some(p.to_affine()),
                            )?;
                            (*point).as_ref().unwrap().constrain_equal(
                                layouter.namespace(|| "[Sinsemilla] cm == expected cm"),
                                &expected_cm,
                            )?;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }

        #[cfg(feature = "debug")]
        halo2api::output_debug_info("SinsemillaCircuit", &_debug_info);

        Ok(result)
    }

    pub fn mock_verify(&self, k: u32) -> Result<(), Vec<VerifyFailure>> {
        let prover = MockProver::<pallas::Base>::run(k, self, vec![]);
        prover.unwrap().verify()
    }
}

impl<T: ISinsemillaCircuit> Circuit<pallas::Base> for SinsemillaCircuit<T> {
    type Config = SinsemillaConfigType;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let commit_domain = global_domain::get_next_commit_domain();
        assert!(
            commit_domain.is_some(),
            "[Sinsemilla] commit: no enougth commit_domain configured"
        );

        let commit_domain = commit_domain.unwrap();
        let gates = &T::get_commit_gate_config(&commit_domain.domain);
        Self::do_configure(meta, commit_domain, &gates)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        SinsemillaChip::<BaseHashDomains, HashDomainsType, DomainFixedBases>::load(
            config.0.sinsemilla_config.clone(),
            &mut layouter,
        )?;
        let ecc_chip = EccChip::construct(config.1.clone());
        let is_with_witnesses = self.input_r.is_some() && self.inputs[0].1.is_some();
        self.do_synthesize(
            &config,
            &ecc_chip,
            &mut layouter,
            &mut BTreeMap::new(),
            is_with_witnesses,
        )?;
        Ok(())
    }
}
