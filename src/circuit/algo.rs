use pasta_curves::{pallas, EpAffine};

use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk,
};

use halo2_gadgets::{
    ecc::{
        self, FixedPoint, FixedPointBaseField, FixedPointShort, ScalarFixed, ScalarFixedShort,
        ScalarVar,
    },
    poseidon::{Hash as PoseidonHash, Pow5Chip as PoseidonChip, Pow5Config as PoseidonConfig},
    primitives::poseidon::{self, ConstantLength},
};

use std::collections::BTreeMap;

use super::base::*;
use super::synthesize::*;
use crate::domains::*;
use crate::types::*;

pub(crate) type ICContext<'a> = (
    &'a mut Option<BTreeMap<String, Vec<String>>>,
    &'a PoseidonConfig<pallas::Base, 3, 2>,
    &'a BTreeMap<String, Option<pallas::Point>>,
);

#[derive(Debug)]
pub(crate) enum ScalarResult {
    None,
    ScalarVarNIPoint(ScalarVar<EpAffine, ecc::chip::EccChip<DomainFixedBases>>),
    ScalarFixedPoint(ScalarFixed<EpAffine, ecc::chip::EccChip<DomainFixedBases>>),
    ScalarFixedPointShort(ScalarFixedShort<EpAffine, ecc::chip::EccChip<DomainFixedBases>>),
}

#[derive(Clone, Debug)]
pub(crate) enum Operand {
    Field(Option<pallas::Base>),
    Point(Option<ecc::Point<EpAffine, ecc::chip::EccChip<DomainFixedBases>>>),
    NIPoint(Option<ecc::NonIdentityPoint<EpAffine, ecc::chip::EccChip<DomainFixedBases>>>),
    Scalar(Option<pallas::Scalar>),
    MagnitudeSign(
        Option<(
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        )>,
    ),
    Cell(Option<AssignedCell<pallas::Base, pallas::Base>>),

    FullField(DomainFullWidth),
    BaseField(DomainBaseField),
    ShortField(DomainShort),
}

impl Operand {
    pub fn to_type_string(&self) -> String {
        match self {
            Self::NIPoint(_) => "NIPoint".to_string(),
            Self::Field(_) => "Field".to_string(),
            Self::Point(_) => "Point".to_string(),
            Self::Scalar(_) => "Scalar".to_string(),
            Self::MagnitudeSign(_) => "MagnitudeSign".to_string(),
            Self::Cell(_) => "Cell".to_string(),
            Self::FullField(_) => "FullField".to_string(),
            Self::BaseField(_) => "BaseField".to_string(),
            Self::ShortField(_) => "ShortField".to_string(),
        }
    }
}

impl AlgoItem {
    fn do_point_compute(
        layouter: &mut impl Layouter<pallas::Base>,
        ecc_chip: &ecc::chip::EccChip<DomainFixedBases>,
        _config: &ConfigData,
        desc: &String,
        operator: &String,
        operand1: &(String, Operand, String), //(name, _, Operand type string)
        operand2: &(String, Operand, String),
    ) -> Result<(Operand, ScalarResult), plonk::Error> {
        let operand1_info = (&operand1.0, &operand1.2, operand1.1.to_type_string());
        let operand2_info = (&operand2.0, &operand2.2, operand2.1.to_type_string());
        let operand1 = &operand1.1;
        let operand2 = operand2.1.clone();

        match operator.as_str() {
            "add" => {
                let desc = format!("add: [{}]", desc);
                match operand1_info.1.as_str() {
                    "Point" => {
                        let operand1: ecc::Point<EpAffine, ecc::chip::EccChip<DomainFixedBases>> =
                            match &operand1 {
                                Operand::Point(Some(p)) => p.clone(),
                                _ => {
                                    assert_synthesize_error_and_panic!(false, &format!("[add-point]: invalid operand1: [{:?}], should be Operand::Point", operand1_info));
                                }
                            };
                        let operand2: ecc::Point<EpAffine, ecc::chip::EccChip<DomainFixedBases>> =
                            match operand2 {
                                Operand::Point(Some(p)) => p,
                                Operand::NIPoint(Some(p)) => p.into(),
                                _ => {
                                    assert_synthesize_error_and_panic!(false, &format!("[add-point]: invalid operand2: [{:?}], should be Operand::Point or NIPoint", operand2_info));
                                }
                            };

                        let ret = operand1.add(layouter.namespace(|| &desc), &operand2)?;
                        Ok((Operand::Point(Some(ret)), ScalarResult::None))
                    }
                    "NIPoint" => {
                        let operand1: ecc::NonIdentityPoint<
                            EpAffine,
                            ecc::chip::EccChip<DomainFixedBases>,
                        > = match &operand1 {
                            Operand::NIPoint(Some(p)) => p.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[add-nipoint]: invalid operand1: [{:?}], should be Operand::NIPoint", operand1_info));
                            }
                        };
                        let operand2: ecc::Point<EpAffine, ecc::chip::EccChip<DomainFixedBases>> =
                            match operand2 {
                                Operand::Point(Some(p)) => p,
                                Operand::NIPoint(Some(p)) => p.into(),
                                _ => {
                                    assert_synthesize_error_and_panic!(false, &format!("[add-nipoint]: invalid operand2: [{:?}], should be Operand::Point or NIPoint", operand2_info));
                                }
                            };

                        let ret = operand1.add(layouter.namespace(|| &desc), &operand2)?;
                        Ok((Operand::Point(Some(ret)), ScalarResult::None))
                    }
                    "Cell" | "CommitCell" => {
                        let operand1: AssignedCell<pallas::Base, pallas::Base> = match &operand1 {
                            Operand::Cell(Some(p)) => p.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[add-cell]: invalid operand1: [{:?}], should be Operand::Cell", operand1_info));
                            }
                        };
                        let operand2: AssignedCell<pallas::Base, pallas::Base> = match operand2 {
                            Operand::Cell(Some(p)) => p,
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[add-cell]: invalid operand2: [{:?}], should be Operand::Cell", operand2_info));
                            }
                        };

                        let ret = operand1
                            .value()
                            .zip(operand2.value())
                            .map(|(operand1, operand2)| operand1 + operand2);
                        Ok((Operand::Field(ret), ScalarResult::None))
                    }
                    _ => {
                        assert_synthesize_error_and_panic!(
                            false,
                            &format!(
                                "[add]: invalid operand1: [{:?}], should be Point, NIPoint or Cell",
                                operand1_info
                            )
                        );
                    }
                }
            }

            "mul" => {
                let desc = format!("mul: [{}]", desc);
                match operand1_info.1.as_str() {
                    "Cell" | "CommitCell" => {
                        let operand1: AssignedCell<pallas::Base, pallas::Base> = match &operand1 {
                            Operand::Cell(Some(p)) => p.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-cell]: invalid operand1: [{:?}], should be Operand::Cell", operand1_info));
                            }
                        };
                        let operand2: AssignedCell<pallas::Base, pallas::Base> = match operand2 {
                            Operand::Cell(Some(p)) => p,
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-cell]: invalid operand2: [{:?}], should be Operand::Cell", operand2_info));
                            }
                        };

                        let ret = operand1
                            .value()
                            .zip(operand2.value())
                            .map(|(operand1, operand2)| operand1 * operand2);
                        Ok((Operand::Field(ret), ScalarResult::None))
                    }
                    "NIPoint" => {
                        let operand1: ecc::NonIdentityPoint<
                            EpAffine,
                            ecc::chip::EccChip<DomainFixedBases>,
                        > = match &operand1 {
                            Operand::NIPoint(Some(p)) => p.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-nipoint]: invalid operand1: [{:?}], should be Operand::NIPoint", operand1_info));
                            }
                        };
                        let operand2: AssignedCell<pallas::Base, pallas::Base> = match operand2 {
                            Operand::Cell(Some(p)) => p,
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-nipoint]: invalid operand2: [{:?}], should be Operand::Cell", operand2_info));
                            }
                        };

                        let (point, var) = operand1.mul(layouter.namespace(|| &desc), &operand2)?;
                        Ok((
                            Operand::Point(Some(point)),
                            ScalarResult::ScalarVarNIPoint(var),
                        ))
                    }
                    "FullField" => {
                        let domain = match &operand1 {
                            Operand::FullField(domain) => domain.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-FullField]: invalid operand1: [{:?}], should be Operand::FullField", operand1_info));
                            }
                        };

                        let operand1 = FixedPoint::from_inner(ecc_chip.clone(), domain);
                        let operand2: Option<pallas::Scalar> = match operand2 {
                            Operand::Scalar(p) => p,
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-FixedPoint]: invalid operand2: [{:?}], should be Operand::Scalar", operand2_info));
                            }
                        };

                        let (ret, scalar) = operand1.mul(layouter.namespace(|| &desc), operand2)?;
                        Ok((
                            Operand::Point(Some(ret)),
                            ScalarResult::ScalarFixedPoint(scalar),
                        ))
                    }
                    "BaseField" => {
                        let domain = match &operand1 {
                            Operand::BaseField(domain) => domain.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[BaseField]: invalid operand1: [{:?}], should be Operand::BaseField", operand1_info));
                            }
                        };

                        let operand1 = FixedPointBaseField::from_inner(ecc_chip.clone(), domain);
                        let operand2: AssignedCell<pasta_curves::Fp, pasta_curves::Fp> =
                            match operand2 {
                                Operand::Cell(Some(p)) => p,
                                _ => {
                                    assert_synthesize_error_and_panic!(false, &format!("[mul-FixedPointBaseField]: invalid operand2: [{:?}], should be Operand::Cell", operand2_info));
                                }
                            };

                        let point = operand1.mul(layouter.namespace(|| &desc), operand2)?;
                        Ok((Operand::Point(Some(point)), ScalarResult::None))
                    }
                    "ShortField" => {
                        let domain = match &operand1 {
                            Operand::ShortField(domain) => domain.clone(),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-ShortField]: invalid operand1: [{:?}], should be Operand::ShortField", operand1_info));
                            }
                        };

                        let operand1 = FixedPointShort::from_inner(ecc_chip.clone(), domain);
                        let (m, s): (
                            AssignedCell<pasta_curves::Fp, pasta_curves::Fp>,
                            AssignedCell<pasta_curves::Fp, pasta_curves::Fp>,
                        ) = match operand2 {
                            Operand::MagnitudeSign(Some((m, s))) => (m, s),
                            _ => {
                                assert_synthesize_error_and_panic!(false, &format!("[mul-FixedPointShort]: invalid operand2: [{:?}], should be Operand::MagnitudeSign", operand2_info));
                            }
                        };

                        let (point, scalar) = operand1.mul(layouter.namespace(|| &desc), (m, s))?;
                        Ok((
                            Operand::Point(Some(point)),
                            ScalarResult::ScalarFixedPointShort(scalar),
                        ))
                    }
                    _ => {
                        assert_synthesize_error_and_panic!(false, &format!("[mul]: invalid operand1: [{:?}], should be NIPoint, FullField, BaseField or ShortField", operand1_info));
                    }
                }
            }

            _ => {
                assert_synthesize_error_and_panic!(
                    false,
                    &format!("[AlgoItem] Invalid operator: [{}][{}]", operator, desc)
                );
            }
        }
    }

    fn compute_two(
        layouter: &mut impl Layouter<pallas::Base>,
        ecc_chip: &ecc::chip::EccChip<DomainFixedBases>,
        config: &ConfigData,
        gate_states: &mut BTreeMap<String, bool>,
        name: &String,
        desc: &String,
        operator: &String,
        operand1: &(String, Operand, String), //(name, _, Operand type string)
        operand2: &(String, Operand, String),
        values: &mut BTreeMap<String, Operand>,
        cell_values: &mut CellValues,
        cell_info: &BTreeMap<String, (String, CellInfo, usize)>,
        context: &mut ICContext,
    ) -> Result<(Operand, ScalarResult), plonk::Error> {
        if context.0.is_some() {
            context
                .0
                .as_mut()
                .unwrap()
                .entry("compute".to_string())
                .or_insert(Vec::new())
                .push(format!(
                    "[{}] = [{}, {}] '{}' [{}, {}]",
                    name, operand1.0, operand1.2, operator, operand2.0, operand2.2
                ));
        }

        let mut result = match operator.as_str() {
            "poseidon" => match operand1.2.as_str() {
                "Cell" | "CommitCell" => {
                    let operand1: AssignedCell<pallas::Base, pallas::Base> = match &operand1.1 {
                        Operand::Cell(Some(p)) => p.clone(),
                        _ => {
                            assert_synthesize_error_and_panic!(false, &format!("[poseidon-operand1]: invalid operand1: [{:?}], should be Operand::Cell", operand1));
                        }
                    };
                    let operand2: AssignedCell<pallas::Base, pallas::Base> = match &operand2.1 {
                        Operand::Cell(Some(p)) => p.clone(),
                        _ => {
                            assert_synthesize_error_and_panic!(false, &format!("[poseidon-operand2]: invalid operand2: [{:?}], should be Operand::Cell", operand2));
                        }
                    };

                    let mut desc = format!("poseidon init: [{}][{}]", name, desc);
                    let poseidon_hasher =
                        PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                            PoseidonChip::construct(context.1.clone()),
                            layouter.namespace(|| &desc),
                        )?;

                    desc = format!("poseidon hash: [{}][{}]", name, desc);
                    let cell = poseidon_hasher.hash(
                        layouter.namespace(|| &desc),
                        [operand1.clone(), operand2.clone()],
                    )?;

                    Ok((Operand::Cell(Some(cell)), ScalarResult::None))
                }
                _ => {
                    assert_synthesize_error_and_panic!(
                        false,
                        &format!(
                            "[poseidon]: Invalid operand1: [{:?}], should be Operand::Cell",
                            operand1
                        )
                    );
                }
            },

            _ => {
                let mut exchange = false;
                if operator == "add" {
                    exchange = operand1.2 == "Point" && operand2.2 == "NIPoint";
                }
                if !exchange && operator == "mul" {
                    if !exchange {
                        exchange = operand2.2 == "NIPoint"
                            || operand2.2 == "FullField"
                            || operand2.2 == "BaseField"
                            || operand2.2 == "ShortField";
                    }
                }

                if exchange {
                    Self::do_point_compute(
                        layouter, ecc_chip, config, desc, operator, operand2, operand1,
                    )
                } else {
                    Self::do_point_compute(
                        layouter, ecc_chip, config, desc, operator, operand1, operand2,
                    )
                }
            }
        }?;

        if name != "" {
            let mut field_values = BTreeMap::new();
            match result.0 {
                Operand::Field(field) => {
                    let cell_data = if cell_info.contains_key(name) {
                        &cell_info[name]
                    } else {
                        let v = cell_info.get(&operand1.0);
                        assert_synthesize_error!(
                            v.is_some(),
                            &format!("[compute_two]: [{}] not in cell_info", operand1.0)
                        );
                        v.unwrap()
                    };

                    field_values.insert(name.clone(), field);
                    let assginedcell_values = assign_region(
                        layouter,
                        config,
                        gate_states,
                        cell_data.2,
                        cell_values,
                        &field_values,
                        context.0,
                    )?;

                    {
                        let v = assginedcell_values.get(name);
                        assert_synthesize_error!(
                            v.is_some(),
                            &format!("[AlgoItem]: [{}] not in assginedcell_values", name)
                        );

                        cell_values.insert(name.clone(), (v.unwrap().clone(), None));
                        result.0 = Operand::Cell(v.unwrap().clone());
                    }
                }
                Operand::Cell(ref cell) => {
                    cell_values
                        .entry(name.clone())
                        .or_insert((cell.clone(), None));
                }
                _ => {}
            }

            values.insert(name.clone(), result.0.clone());
        }

        Ok(result)
    }

    fn compute(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ecc_chip: &ecc::chip::EccChip<DomainFixedBases>,
        config: &ConfigData,
        gate_states: &mut BTreeMap<String, bool>,
        values: &mut BTreeMap<String, Operand>,
        cell_values: &mut CellValues,
        cell_info: &BTreeMap<String, (String, CellInfo, usize)>,
        context: &mut ICContext,
    ) -> Result<(Operand, ScalarResult), plonk::Error> {
        if self.operand2.is_none() {
            let v = values.get(&self.operand1.0);
            assert_synthesize_error!(
                v.is_some(),
                &format!("[AlgoItem]: operand1[{}] not in values", self.operand1.0)
            );
            return Ok((v.unwrap().clone(), ScalarResult::None));
        }

        let operand2 = self.operand2.as_ref().unwrap();

        let v1 = values.get(&self.operand1.0);
        let v2 = values.get(&operand2.0);
        assert_synthesize_error!(
            v1.is_some() && v2.is_some(),
            &format!(
                "[AlgoItem]: [{}] or [{}] not in values",
                self.operand1.0, operand2.0
            )
        );

        Self::compute_two(
            layouter,
            ecc_chip,
            config,
            gate_states,
            &self.name,
            &self.desc,
            &self.operator,
            &(
                self.operand1.0.clone(),
                v1.unwrap().clone(),
                self.operand1.1.clone(),
            ),
            &(operand2.0.clone(), v2.unwrap().clone(), operand2.1.clone()),
            values,
            cell_values,
            cell_info,
            context,
        )
    }
}

impl Algo {
    pub(crate) fn compute(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        ecc_chip: &ecc::chip::EccChip<DomainFixedBases>,
        config: &ConfigData,
        gate_states: &mut BTreeMap<String, bool>,
        values: &mut BTreeMap<String, Operand>,
        cell_values: &mut CellValues,
        cell_info: &BTreeMap<String, (String, CellInfo, usize)>,
        context: &mut ICContext,
    ) -> Result<(Operand, ScalarResult), plonk::Error> {
        assert_synthesize_error!(
            self.items.len() > 0,
            &format!("[Algo]: no items configured: [{}]", self.desc)
        );

        let (mut operand, mut ret) = self.items[0].1.compute(
            layouter,
            ecc_chip,
            config,
            gate_states,
            values,
            cell_values,
            cell_info,
            context,
        )?;

        let mut prev_name = self.items[0].1.name.clone();
        let mut prev_operand = operand.clone();
        for i in 1..self.items.len() {
            let (operator, item) = &self.items[i];
            let (_operand, _ret) = item.compute(
                layouter,
                ecc_chip,
                config,
                gate_states,
                values,
                cell_values,
                cell_info,
                context,
            )?;

            let operand2 = if item.operand2.is_some() {
                (item.name.clone(), _operand.to_type_string())
            } else {
                item.operand1.clone()
            };
            (operand, ret) = AlgoItem::compute_two(
                layouter,
                ecc_chip,
                config,
                gate_states,
                &item.name,
                &item.desc,
                operator,
                &(
                    prev_name.clone(),
                    prev_operand.clone(),
                    prev_operand.to_type_string(),
                ),
                &(operand2.0, _operand, operand2.1),
                values,
                cell_values,
                cell_info,
                context,
            )?;

            prev_name = item.name.clone();
            prev_operand = operand.clone();
        }
        Ok((operand, ret))
    }
}
