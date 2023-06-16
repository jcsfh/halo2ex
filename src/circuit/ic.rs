use group::Curve;
use pasta_curves::pallas;

use halo2_proofs::{
    circuit::{floor_planner, AssignedCell, Layouter},
    plonk::{self, Expression},
    poly::Rotation,
};

use halo2_gadgets::{
    ecc::{chip::EccChip, NonIdentityPoint, Point},
    poseidon::Pow5Chip as PoseidonChip,
    primitives::poseidon,
    sinsemilla::{
        chip::SinsemillaChip,
        merkle::{chip::MerkleChip, MerklePath},
    },
    utilities::{lookup_range_check::LookupRangeCheckConfig, UtilitiesInstructions},
};

use std::collections::{BTreeMap, HashMap};
use std::convert::TryInto;

use super::{algo::*, base::*, synthesize::*};
use crate::{
    base,
    consts::*,
    domains::*,
    global, halo2api,
    primitives::{tree::*, utils::*, value::*},
    sinsemilla::{circuit::*, config::*},
    types::*,
};

#[derive(Clone, Debug, Default)]
pub struct ICCircuit<T: Default + Clone + ICConfig> {
    pub(crate) paths:
        Option<BTreeMap<String, (String, String, Option<[DomainMerkleHash; MERKLE_DEPTH]>)>>, // (domain_name, leaf_name, path)
    pub(crate) positions: Option<BTreeMap<String, Option<u32>>>,
    pub(crate) fields: Option<BTreeMap<String, (Option<pallas::Base>, Option<pallas::Base>, bool)>>, // (x, y, is_two)
    pub(crate) points: Option<BTreeMap<String, Option<pallas::Point>>>,
    pub(crate) nipoints: Option<BTreeMap<String, Option<pallas::Point>>>,
    pub(crate) scalars: Option<BTreeMap<String, Option<pallas::Scalar>>>,
    pub(crate) values: Option<BTreeMap<String, Option<(ValueType<T::Value>, ValueType<T::Value>)>>>, //old, new

    constraint_points: BTreeMap<String, Option<pallas::Point>>,
    is_with_witnesses: bool,
}

impl<T: Default + Clone + ICConfig> ICCircuit<T> {
    pub(crate) fn to_gates_config(configs: &Vec<GateConfig>) -> Vec<GateInfo> {
        configs
            .iter()
            .map(|config| GateInfo::from(config))
            .collect()
    }

    pub(crate) fn to_single_algos_config(configs: &Vec<AlgoConfig>) -> Vec<Algo> {
        configs.iter().map(|config| Algo::from(config)).collect()
    }

    pub(crate) fn to_algos_config(configs: &Vec<Vec<AlgoConfig>>) -> Vec<Vec<Algo>> {
        configs
            .iter()
            .map(|algos| Self::to_single_algos_config(algos))
            .collect::<Vec<Vec<_>>>()
    }

    pub fn add_field(&mut self, name: &str, v: &pallas::Base) {
        if self.fields.is_none() {
            self.fields = Some(BTreeMap::new());
        }
        self.fields
            .as_mut()
            .unwrap()
            .insert(name.to_string(), (Some(v.clone()), None, false));
        self.is_with_witnesses = true;
    }

    pub fn add_point(&mut self, name: &str, v: &pallas::Point) {
        if self.points.is_none() {
            self.points = Some(BTreeMap::new());
        }
        self.points
            .as_mut()
            .unwrap()
            .insert(name.to_string(), Some(*v));
        self.is_with_witnesses = true;
    }

    pub fn add_nipoint(&mut self, name: &str, v: &pallas::Point) {
        if self.nipoints.is_none() {
            self.nipoints = Some(BTreeMap::new());
        }
        self.nipoints
            .as_mut()
            .unwrap()
            .insert(name.to_string(), Some(*v));
        self.is_with_witnesses = true;
    }

    pub fn add_scalar(&mut self, name: &str, v: &pallas::Scalar) {
        if self.scalars.is_none() {
            self.scalars = Some(BTreeMap::new());
        }
        self.scalars
            .as_mut()
            .unwrap()
            .insert(name.to_string(), Some(v.clone()));
        self.is_with_witnesses = true;
    }

    pub fn add_values(&mut self, name: &str, v: &(ValueType<T::Value>, ValueType<T::Value>)) {
        if self.values.is_none() {
            self.values = Some(BTreeMap::new());
        }
        self.values
            .as_mut()
            .unwrap()
            .insert(name.to_string(), Some(*v));
        self.is_with_witnesses = true;
    }

    pub fn add_merkle_data(
        &mut self,
        name: &str,
        path: &(&str, &str, [DomainMerkleHash; MERKLE_DEPTH]),
        pos: u32,
    ) {
        if self.paths.is_none() {
            self.paths = Some(BTreeMap::new());
        }
        if self.positions.is_none() {
            self.positions = Some(BTreeMap::new());
        }

        self.paths.as_mut().unwrap().insert(
            name.to_string(),
            (path.0.to_string(), path.1.to_string(), Some(path.2)),
        );
        self.positions
            .as_mut()
            .unwrap()
            .insert(name.to_string(), Some(pos));
        self.is_with_witnesses = true;
    }

    pub fn add_constraint_point(&mut self, name: &str, v: &pallas::Point) {
        self.constraint_points.insert(name.to_string(), Some(*v));
    }

    pub fn copy_none_values(&mut self, other: &Self) {
        self.fields = other.fields.as_ref().map(|values| {
            values
                .iter()
                .map(|(name, (_, _, is_two))| (name.clone(), (None, None, *is_two)))
                .collect()
        });
        self.points = other.points.as_ref().map(|values| {
            values
                .iter()
                .map(|(name, _)| (name.clone(), None))
                .collect()
        });
        self.nipoints = other.nipoints.as_ref().map(|values| {
            values
                .iter()
                .map(|(name, _)| (name.clone(), None))
                .collect()
        });
        self.scalars = other.scalars.as_ref().map(|values| {
            values
                .iter()
                .map(|(name, _)| (name.clone(), None))
                .collect()
        });
    }
}

impl<T: Default + Clone + ICConfig> ISinsemillaCircuit for ICCircuit<T> {
    fn get_commit_gate_config(domain: &String) -> Vec<GateInfo> {
        Self::to_gates_config(T::get_commit_gate_configs(domain).as_ref().unwrap())
    }
}

impl<T: Default + Clone + ICConfig> UtilitiesInstructions<pallas::Base> for ICCircuit<T> {
    type Var = AssignedCell<pallas::Base, pallas::Base>;
}

impl<T: Default + Clone + ICConfig> plonk::Circuit<pallas::Base> for ICCircuit<T> {
    type Config = ConfigData;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
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

        let mut desc = String::new();
        let (gates, algos) = &T::get_ic_configs();
        let gates = Self::to_gates_config(&gates);
        let algos = Self::to_algos_config(&algos);
        assert!(
            gates.len() > 0 && gates.len() <= algos.len(),
            "(ICCircuit::configure) gates len[{}] is zero or greater than algos[{}]",
            gates.len(),
            algos.len()
        );

        let qs = gates
            .iter()
            .zip(&algos[0..gates.len()])
            .map(|(gate, algos)| {
                let q = meta.selector();

                desc = format!("(ICCircuit::configure) create_gate: [{}]", gate.name);
                meta.create_gate(base::string_to_static_str(&desc), |meta| {
                    let q = meta.query_selector(q);

                    let values = gate
                        .cells
                        .iter()
                        .filter_map(|cell| {
                            if cell.celltype == CellType::Input || cell.celltype == CellType::Instance {
                                let rotation = match cell.row {
                                    RowType::Cur => Rotation::cur(),
                                    RowType::Next => Rotation::next(),
                                    RowType::Prev => Rotation::prev(),
                                };

                                let value = match cell.coltype {
                                    ColType::Advice => meta.query_advice(advices[cell.col], rotation),
                                    _ => {
                                        panic!(
                                            "(ICCircuit::configure) create_gate: not supported cell type: [{:?}]",
                                            cell.coltype
                                        )
                                    }
                                };

                                Some((cell.name.clone(), value))
                            }
                            else {
                                None
                            }
                        })
                        .collect::<BTreeMap<_, _>>();

                    let wholes = algos.iter().map(|algo| {
                        let mut whole = Expression::Constant(pallas::Base::zero());

                        for (operator, item) in &algo.items {
                            let item_result = match item.operator.as_str() {
                                "add" => values[&item.operand1.0].clone() + values[&item.operand2.clone().unwrap().0].clone(),
                                "sub" => values[&item.operand1.0].clone() - values[&item.operand2.clone().unwrap().0].clone(),
                                "mul" => values[&item.operand1.0].clone() * values[&item.operand2.clone().unwrap().0].clone(),
                                "boolean_neg" => Expression::Constant(pallas::Base::one()) - values[&item.operand1.0].clone(),
                                _ => values[&item.operand1.0].clone(),
                            };

                            //just for debug
                            //let tmp = ("".to_string(), "".to_string());
                            //let operand2 = if item.operand2.is_some() {item.operand2.as_ref().unwrap()} else {&tmp};
                            //println!("[{}] = [{}, {}] '{}' [{}, {}]", item.name, item.operand1.0, item.operand1.1, item.operator, operand2.0, operand2.1);                            

                            match operator.as_str() {
                                "add" | "" => whole = whole + item_result,
                                "sub" => whole = whole - item_result,
                                "mul" => whole = whole * item_result,
                                _ => panic!("(ICCircuit::configure) Invalid operator: [{}]", operator),
                            }
                        }

                        (algo.desc.clone(), whole)
                    }).collect::<Vec<_>>();

                    wholes.iter().map(move |(_name, poly)| q.clone() * poly.clone())
                        .collect::<Vec<_>>()
                        .into_iter()
                });
                q
            })
            .collect::<Vec<_>>();

        let table_idx = meta.lookup_table_column();
        let lookup = (
            table_idx,
            meta.lookup_table_column(),
            meta.lookup_table_column(),
        );

        let primary = meta.instance_column();
        meta.enable_equality(primary);

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

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
        let rc_a = lagrange_coeffs[2..5].try_into().unwrap();
        let rc_b = lagrange_coeffs[5..8].try_into().unwrap();

        meta.enable_constant(lagrange_coeffs[0]);

        let range_check = LookupRangeCheckConfig::configure(meta, advices[9], table_idx);

        let ecc_config =
            EccChip::<DomainFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        let poseidon_config = PoseidonChip::configure::<poseidon::P128Pow5T3>(
            meta,
            advices[6..9].try_into().unwrap(),
            advices[5],
            rc_a,
            rc_b,
        );

        let (sinsemilla_config_1, merkle_config_1) = {
            let sinsemilla_config_1 = SinsemillaChip::configure(
                meta,
                advices[..5].try_into().unwrap(),
                advices[6],
                lagrange_coeffs[0],
                lookup,
                range_check,
            );
            let merkle_config_1 = MerkleChip::configure(meta, sinsemilla_config_1.clone());

            (sinsemilla_config_1, merkle_config_1)
        };

        let (sinsemilla_config_2, merkle_config_2) = {
            let sinsemilla_config_2 = SinsemillaChip::configure(
                meta,
                advices[5..].try_into().unwrap(),
                advices[7],
                lagrange_coeffs[1],
                lookup,
                range_check,
            );
            let merkle_config_2 = MerkleChip::configure(meta, sinsemilla_config_2.clone());

            (sinsemilla_config_2, merkle_config_2)
        };

        let commit_configs = T::get_commit_configs();
        let commit_configs = if commit_configs.is_some()
            && commit_configs.as_ref().unwrap().len() > 0
        {
            Some(
                commit_configs
                    .as_ref()
                    .unwrap()
                    .iter()
                    .map(
                        |(
                            is_short_commit,
                            commit_name,
                            (domain_name, num_window),
                            inputs,
                            rname,
                        )| {
                            let commit_domain = HashDomainsType {
                                domain: domain_name.clone(),
                                num_windows: *num_window,
                                is_hash_domain: false,
                            };
                            let gates = &Self::get_commit_gate_config(&domain_name);

                            let sinsemilla_config = if commit_name.starts_with(SIGN_OF_NEW_VALUE) {
                                &sinsemilla_config_2
                            } else {
                                &sinsemilla_config_1
                            };
                            let commit_config = CommitConfig::configure(
                                meta,
                                advices,
                                sinsemilla_config.clone(),
                                commit_domain.clone(),
                                gates,
                            );
                            (
                                commit_name.clone(),
                                (
                                    *is_short_commit,
                                    commit_config,
                                    commit_domain,
                                    inputs.clone(),
                                    rname.clone(),
                                ),
                            )
                        },
                    )
                    .collect::<Vec<_>>(),
            )
        } else {
            None
        };

        let instance_info = T::get_instance_order()
            .iter()
            .enumerate()
            .map(|(i, name)| (name.clone(), i))
            .collect::<BTreeMap<_, _>>();

        ConfigData {
            gates: gates.to_vec(),
            algos,
            primary,
            instance_info,
            qs,
            advices,
            ecc_config,
            poseidon_config,
            merkle_config_1,
            merkle_config_2,
            sinsemilla_config_1,
            commit_configs,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), plonk::Error> {
        let config = config.clone();
        SinsemillaChip::load(config.sinsemilla_config_1.clone(), &mut layouter)?;
        let ecc_chip = EccChip::construct(config.ecc_config.clone());

        let mut _debug_info = if !self.is_with_witnesses && cfg!(feature = "debug") {
            Some(BTreeMap::new())
        } else {
            None
        };

        let mut fields = self.fields.clone().unwrap_or(BTreeMap::default());
        let mut positions = self.positions.clone().unwrap_or(BTreeMap::default());
        let mut paths = self.paths.clone().unwrap_or(BTreeMap::default());
        let mut points = self.points.clone().unwrap_or(BTreeMap::default());
        let mut nipoints = self.nipoints.clone().unwrap_or(BTreeMap::default());
        let mut values = self.values.clone().unwrap_or(BTreeMap::default());
        let mut scalars = self.scalars.clone().unwrap_or(BTreeMap::new());
        let mut constraint_points = self.constraint_points.clone();

        let commit_configs = config.commit_configs.clone().unwrap_or(Vec::default());

        let mut eccpoint_values = HashMap::new();
        let mut nipoint_values = HashMap::new();
        let mut net_values = HashMap::new();

        let mut cell_values = BTreeMap::new();
        let mut operands = BTreeMap::new();
        let mut cell_info = BTreeMap::new();

        for i in 0..config.gates.len() {
            let gate = &config.gates[i];
            cell_info.append(
                &mut gate
                    .cells
                    .iter()
                    .map(|cell| {
                        let attr = cell.attr.clone().unwrap_or("".to_string());
                        let attr = attr.trim();

                        if attr == ATTRIBUTE_VALUE {
                            let is_old = cell.name.starts_with(SIGN_OF_OLD_VALUE);
                            let cellname = if is_old {
                                &cell.name[SIGN_OF_OLD_VALUE.len()..]
                            }
                            else if cell.name.starts_with(SIGN_OF_NEW_VALUE) {
                                &cell.name[SIGN_OF_NEW_VALUE.len()..]
                            }
                            else {
                                panic!("[ICCircuit::synthesize] Invalid value name [{}] configured, should start with 'old_' or 'new_'", cell.name);
                            };

                            values.entry(cellname.to_string()).or_insert(None);
                        }
                        if attr.starts_with(ATTRIBUTE_MERKLEPATH) {
                            let attrs: Vec<_> = attr[ATTRIBUTE_MERKLEPATH.len()..].split("#").map(|v| v.trim()).collect();
                            paths.entry(attrs[0].to_string()).or_insert((attrs[1].to_string(), attrs[2].to_string(), None));
                            positions.entry(attrs[0].to_string()).or_insert(None);
                            points.entry(attrs[2].to_string()).or_insert(None);
                        }

                        (cell.name.clone(), (gate.name.clone(), cell.clone(), i))
                    })
                    .collect::<BTreeMap<_, _>>(),
            );
        }

        {
            let mut insert_none_value = |operand: &(String, String)| {
                assert_synthesize_error!(operand.0 != "", "operand name configured must not be ''");

                match operand.1.as_str() {
                    "Cell" | "Field" => {
                        fields
                            .entry(operand.0.clone())
                            .or_insert((None, None, false));
                    }
                    "Point" => {
                        points.entry(operand.0.clone()).or_insert(None);
                    }
                    "NIPoint" => {
                        nipoints.entry(operand.0.clone()).or_insert(None);
                    }
                    "Scalar" => {
                        scalars.entry(operand.0.clone()).or_insert(None);
                    }
                    "FullField" => {
                        debug_assert!(
                            global::get_fixedbasefull(&operand.0).is_some(),
                            "[{}] not configured for FullField",
                            operand.0
                        );
                        let v = global::get_fixedbasefull(&operand.0).clone().unwrap();
                        operands.insert(operand.0.clone(), Operand::FullField(v));
                    }
                    "BaseField" => {
                        debug_assert!(
                            global::get_fixedpointbasefield(&operand.0).is_some(),
                            "[{}] not configured for BaseField",
                            operand.0
                        );
                        let v = global::get_fixedpointbasefield(&operand.0).clone().unwrap();
                        operands.insert(operand.0.clone(), Operand::BaseField(v));
                    }
                    "ShortField" => {
                        debug_assert!(
                            global::get_fixedpointshort(&operand.0).is_some(),
                            "[{}] not configured for ShortField",
                            operand.0
                        );
                        let v = global::get_fixedpointshort(&operand.0).clone().unwrap();
                        operands.insert(operand.0.clone(), Operand::ShortField(v));
                    }
                    "MagnitudeSign" | "CommitCell" => {}
                    _ => {
                        assert_synthesize_error_and_panic!(false, &format!("[ICCircuit::synthesize] Invalid operand type configured: [{}] for [{}]", operand.1, operand.0));
                    }
                };
                Ok(())
            };

            for i in config.gates.len()..config.algos.len() {
                let algo = &config.algos[i][0];
                assert_synthesize_error!(
                    algo.name == SIGN_OF_CONSTRAINT || algo.name == SIGN_OF_CONSTRAINT_COMMIT,
                    &format!(
                        "[ICCircuit::synthesize] Invalid constraint name configured: [{}]",
                        algo.name
                    )
                );

                for (_operator, item) in &algo.items {
                    insert_none_value(&item.operand1)?;
                    if item.operand2.is_some() {
                        insert_none_value(item.operand2.as_ref().unwrap())?;
                    }

                    if !self.is_with_witnesses {
                        if item.name.starts_with(SIGN_OF_CONSTRAINT) {
                            constraint_points.entry(item.name.clone()).or_insert(None);
                        }
                    }
                }
            }

            if !self.is_with_witnesses {
                for (_, (_, _, _, inputs, rname)) in &commit_configs {
                    for input in inputs {
                        if input.1 != "" {
                            insert_none_value(&input)?;
                        }
                    }
                    insert_none_value(&(rname.clone(), "Scalar".to_string()))?;
                }
            }
        }

        for (name, v) in std::iter::empty().chain(&fields).chain(
            &values
                .iter()
                .map(|(name, v)| {
                    let v = v.map(|v| {
                        (
                            v.0.to_base(), //old
                            v.1.to_base(), //new
                            true,
                        )
                    });
                    (name.clone(), v.unwrap_or((None, None, true)))
                })
                .collect::<BTreeMap<_, _>>(),
        ) {
            let desc = format!("[ICCircuit::synthesize] witness [{}]", name);
            let v0 = halo2api::load_private(
                self,
                &mut layouter,
                &desc,
                &config.advices,
                0,
                &v.0,
                (
                    &mut _debug_info,
                    &if v.2 {
                        format!("old_{}", name)
                    } else {
                        name.clone()
                    },
                ),
            )?;
            if v.2 {
                let v1 = halo2api::load_private(
                    self,
                    &mut layouter,
                    &desc,
                    &config.advices,
                    0,
                    &v.1,
                    (&mut _debug_info, &format!("new_{}", name)),
                )?;
                cell_values.insert(name.clone(), (Some(v0), Some(v1)));
            } else {
                cell_values.insert(name.clone(), (Some(v0), None));
            }
        }

        for (name, p) in &points {
            let desc = format!(
                "[ICCircuit::synthesize] Convert point[{}] to eccpoint",
                name
            );
            let p = Point::new(
                ecc_chip.clone(),
                layouter.namespace(|| &desc),
                p.as_ref().map(|p| p.to_affine()),
            )?;
            eccpoint_values.insert(name.clone(), Some(p));
        }

        for (name, p) in &nipoints {
            let desc = format!(
                "[ICCircuit::synthesize] Convert nipoint[{}] to NonIdentityPoint",
                name
            );
            let _p = p.clone();
            let p = NonIdentityPoint::new(
                ecc_chip.clone(),
                layouter.namespace(|| &desc),
                p.map(|p| p.to_affine()),
            )?;

            nipoint_values.insert(name.clone(), Some(p));
        }

        // value integrity.
        for (name, _v) in &values {
            let value = cell_values.get(name);
            assert_synthesize_error!(
                value.is_some(),
                &format!("[ICCircuit::synthesize] [{}] not in cell_values", name)
            );

            let v_net = {
                let (v_old, v_new) = value.unwrap().clone();
                assert_synthesize_error!(
                    v_old.is_some() && v_new.is_some(),
                    &format!("[ICCircuit::synthesize] value[{}] is none", name)
                );

                cell_values.insert(
                    format!("{}{}", SIGN_OF_OLD_VALUE, name),
                    (Some(v_old.clone().unwrap()), None),
                );
                cell_values.insert(
                    format!("{}{}", SIGN_OF_NEW_VALUE, name),
                    (Some(v_new.clone().unwrap()), None),
                );

                let (v_old, v_new) = (
                    v_old.as_ref().unwrap().value(),
                    v_new.as_ref().unwrap().value(),
                );
                let (v_old, v_new) = (v_old.map(|v_old| *v_old), v_new.map(|v_new| *v_new));

                let magnitude_sign = v_old.zip(v_new).map(|(v_old, v_new)| {
                    let is_negative = v_old < v_new;
                    let magnitude = if is_negative {
                        v_new - v_old
                    } else {
                        v_old - v_new
                    };
                    let sign = if is_negative {
                        -pallas::Base::one()
                    } else {
                        pallas::Base::one()
                    };
                    (magnitude, sign)
                });

                let magnitude_name = format!("{}{}", SIGN_OF_MAGNITUDE, name);
                let sign_name = format!("{}{}", SIGN_OF_SIGN, name);

                let mut desc = format!("[ICCircuit::synthesize][{}] v_net magnitude", name);
                let magnitude = halo2api::load_private(
                    self,
                    &mut layouter,
                    &desc,
                    &config.advices,
                    9,
                    &magnitude_sign.map(|m_s| m_s.0),
                    (&mut _debug_info, &magnitude_name),
                )?;

                desc = format!("[ICCircuit::synthesize] [{}] v_net sign", name);
                let sign = halo2api::load_private(
                    self,
                    &mut layouter,
                    &desc,
                    &config.advices,
                    9,
                    &magnitude_sign.map(|m_s| m_s.1),
                    (&mut _debug_info, &sign_name),
                )?;

                cell_values.insert(magnitude_name, (Some(magnitude.clone()), None));
                cell_values.insert(sign_name, (Some(sign.clone()), None));

                (magnitude, sign)
            };

            net_values.insert(name.clone(), Some(v_net));
        }

        // merkle path validity check.
        for (name, (domain_name, leaf_name, path)) in &paths {
            let anchor = {
                let path: Option<[pallas::Base; MERKLE_DEPTH]> =
                    path.map(|typed_path| gen_const_array(|i| typed_path[i].value()));
                let merkle_inputs = MerklePath::construct(
                    MerkleChip::construct(config.merkle_config_1.clone()),
                    MerkleChip::construct(config.merkle_config_2.clone()),
                    BaseHashDomains {
                        domain: domain_name.clone(),
                        is_hash_domain: true,
                    },
                    positions[name],
                    path,
                );

                let v = cell_values.get(leaf_name);
                let leaf = if v.is_some() {
                    v.unwrap().0.clone().unwrap()
                } else {
                    let v = eccpoint_values.get(leaf_name);
                    assert_synthesize_error!(
                        v.is_some() && v.unwrap().is_some(),
                        &format!(
                            "[ICCircuit::synthesize] [{}] not in eccpoint_values",
                            leaf_name
                        )
                    );
                    v.unwrap().as_ref().unwrap().extract_p().inner().clone()
                };

                let desc = format!("[ICCircuit::synthesize] MerkleCRH[{}]", name);
                merkle_inputs.calculate_root(layouter.namespace(|| &desc), leaf)?
            };
            cell_values.insert(
                SIGN_OF_ANCHOR.to_string() + &name.clone(),
                (Some(anchor), None),
            );
        }

        // collect operands for computation
        let mut _operands = std::iter::empty()
            .chain(
                cell_values
                    .iter()
                    .map(|(name, (v1, _v2))| (name.clone(), Operand::Cell(v1.clone())))
                    .collect::<BTreeMap<_, _>>(),
            )
            .chain(
                nipoint_values
                    .iter()
                    .map(|(name, v)| (name.clone(), { Operand::NIPoint(v.clone()) }))
                    .collect::<BTreeMap<_, _>>(),
            )
            .chain(
                eccpoint_values
                    .iter()
                    .map(|(name, v)| (name.clone(), Operand::Point(v.clone())))
                    .collect::<BTreeMap<_, _>>(),
            )
            .chain(
                net_values
                    .iter()
                    .map(|(name, v)| (name.clone(), Operand::MagnitudeSign(v.clone())))
                    .collect::<BTreeMap<_, _>>(),
            )
            .chain(
                scalars
                    .iter()
                    .map(|(name, v)| (name.clone(), Operand::Scalar(v.clone())))
                    .collect::<BTreeMap<_, _>>(),
            )
            .collect::<BTreeMap<_, _>>();
        operands.append(&mut _operands);

        let mut gate_states = BTreeMap::new();
        compute_and_constraint(
            &mut layouter,
            &ecc_chip,
            SIGN_OF_CONSTRAINT,
            &config,
            &mut gate_states,
            &mut operands,
            &mut cell_values,
            &cell_info,
            &mut (
                &mut _debug_info,
                &config.poseidon_config.clone(),
                &constraint_points,
            ),
        )?;

        // check commits
        for (commit_name, (is_short_commit, commit_config, commit_domain, inputs, rname)) in
            &commit_configs
        {
            let random = scalars.get(rname).unwrap_or(&None).clone();

            let mut input_list = Vec::new();
            let mut input_map = BTreeMap::new();

            for (name, _) in inputs {
                let v = operands.get(name);
                assert_synthesize_error!(
                    v.is_some(),
                    &format!(
                        "[ICCircuit::synthesize] commit input name[{}] not in operands",
                        name
                    )
                );

                let v = v.unwrap();
                let v = match v {
                    Operand::Field(v) => (v.clone(), None),
                    Operand::Point(Some(v)) => {
                        let point = v.inner();
                        input_map.insert(name.clone(), (Some(point.x()), Some(point.y()), 0));

                        (
                            point.x().value().map(|v| *v),
                            if *is_short_commit {
                                None
                            } else {
                                point.y().value().map(|v| *v)
                            },
                        )
                    }
                    Operand::NIPoint(Some(v)) => {
                        let point = v.inner();
                        input_map.insert(name.clone(), (Some(point.x()), Some(point.y()), 0));

                        (
                            point.x().value().map(|v| *v),
                            if *is_short_commit {
                                None
                            } else {
                                point.y().value().map(|v| *v)
                            },
                        )
                    }
                    Operand::Cell(Some(v)) => {
                        input_map.insert(name.clone(), (Some(v.clone()), None, 0));
                        (v.value().map(|v| v.clone()), None)
                    }
                    _ => {
                        assert_synthesize_error_and_panic!(false, &format!("[ICCircuit::synthesize] the operand[{}] of commit input name[{}] is invalid or None", v.to_type_string(), name));
                    }
                };
                input_list.push((name.clone(), v.0, v.1));
            }

            let circuit = SinsemillaCircuit::<Self>::new(
                *is_short_commit,
                &commit_domain.domain,
                &input_list,
                random,
                &Vec::default(),
            );

            let cm = circuit.do_synthesize(
                &(
                    commit_config.clone(),
                    config.ecc_config.clone(),
                    commit_config.gates.clone(),
                ),
                &ecc_chip,
                &mut layouter,
                &mut input_map,
                self.is_with_witnesses,
            )?;

            match cm {
                PointResult::X(x) => {
                    operands.insert(
                        commit_name.clone(),
                        Operand::Cell(x.map(|x| x.inner().clone())),
                    );
                }
                PointResult::Point(p) => {
                    operands.insert(commit_name.clone(), Operand::Point(p));
                }
            }
        }

        compute_and_constraint(
            &mut layouter,
            &ecc_chip,
            SIGN_OF_CONSTRAINT_COMMIT,
            &config,
            &mut gate_states,
            &mut operands,
            &mut cell_values,
            &cell_info,
            &mut (
                &mut _debug_info,
                &config.poseidon_config.clone(),
                &constraint_points,
            ),
        )?;

        for i in 0..config.gates.len() {
            let gate = &config.gates[i];
            if !gate_states.contains_key(&gate.name) {
                assign_region(
                    &mut layouter,
                    &config,
                    &mut gate_states,
                    i,
                    &mut cell_values,
                    &BTreeMap::new(),
                    &mut _debug_info,
                )?;
            }
        }

        #[cfg(feature = "debug")]
        halo2api::output_debug_info("ICCircuit", &_debug_info);

        Ok(())
    }
}
