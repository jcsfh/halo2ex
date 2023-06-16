use group::Curve;
use pasta_curves::pallas;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk,
};

use halo2_gadgets::ecc;

use std::collections::BTreeMap;

use super::algo::*;
use super::base::*;
use crate::consts::*;
use crate::domains::*;
use crate::halo2api;
use crate::types::*;

pub(crate) fn assign_region(
    layouter: &mut impl Layouter<pallas::Base>,
    config: &ConfigData,
    gate_states: &mut BTreeMap<String, bool>,
    gate_index: usize,
    cell_values: &mut CellValues,
    field_values: &BTreeMap<String, Option<pallas::Base>>,
    _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
) -> Result<BTreeMap<String, Option<AssignedCell<pallas::Base, pallas::Base>>>, plonk::Error> {
    let mut assginedcell_values = BTreeMap::new();
    let gate = &config.gates[gate_index];
    let state = gate_states.get_mut(&gate.name);
    if state.is_some() {
        return Ok(assginedcell_values);
    }

    let q = &config.qs[gate_index];
    let advices = &config.advices;
    let primary = &config.primary;
    let instance_info = &config.instance_info;

    let desc = format!("assign_region: [{}]", gate.name);
    layouter.assign_region(
        || &desc,
        |mut region| {
            for cell in &gate.cells {
                let row = match cell.row {
                    RowType::Cur => 0,
                    RowType::Next => 1,
                    _ => panic!("assign_region: wrong row configured: [{:?}]", cell.row),
                };

                if cell.celltype == CellType::Instance {
                    let v = *instance_info.get(&cell.name).unwrap_or(&usize::MAX);
                    assert_synthesize_error!(
                        v < instance_info.len(),
                        &format!(
                            "assign_region: [{}] not in instance_info or invalid value[{}]",
                            cell.name, v
                        )
                    );

                    let desc = format!("assign_region: pub input[{}]", cell.name);
                    halo2api::assign_advice_from_instance(
                        &mut region,
                        || &desc,
                        primary,
                        v,
                        advices,
                        cell.col,
                        row,
                        (_debug_info, &format!("[{}]:  {}", gate.name, cell.name)),
                    )?;
                } else if cell.celltype == CellType::Input {
                    let field_value = field_values.get(&cell.name);
                    let cell_value = cell_values.get(&cell.name);
                    assert_synthesize_error!(
                        field_value.is_some() || cell_value.is_some(),
                        &format!(
                            "assign_region: [{}] not in cell_values and field_values",
                            cell.name
                        )
                    );

                    if field_value.is_none() {
                        let desc = format!("assign_region: copy_advice[{}]", &cell.name);
                        let value = cell_value.unwrap();
                        assert_synthesize_error!(
                            value.0.is_some(),
                            &format!("assign_region: [{}]: value.0 is none", desc)
                        );

                        halo2api::copy_advice(
                            value.0.as_ref().unwrap(),
                            &mut region,
                            || &desc,
                            advices,
                            cell.col,
                            row,
                            (_debug_info, &format!("[{}]:  {}", gate.name, cell.name)),
                        )?;
                    } else {
                        let field = *field_value.unwrap();

                        let desc = format!("assign_region: assign_advice[{}]", cell.name);
                        let v = halo2api::assign_advice(
                            &mut region,
                            || &desc,
                            advices,
                            cell.col,
                            row,
                            || field.ok_or(plonk::Error::Synthesis),
                            (_debug_info, &format!("[{}]:  {}", gate.name, cell.name)),
                        )?;
                        assginedcell_values.insert(cell.name.clone(), Some(v));
                    }
                }
            }
            q.enable(&mut region, 0)
        },
    )?;

    gate_states.insert(gate.name.clone(), true);
    Ok(assginedcell_values)
}

pub(crate) fn compute_and_constraint(
    layouter: &mut impl Layouter<pallas::Base>,
    ecc_chip: &ecc::chip::EccChip<DomainFixedBases>,
    algo_type: &str,
    config: &ConfigData,
    gate_states: &mut BTreeMap<String, bool>,
    operands: &mut BTreeMap<String, Operand>,
    cell_values: &mut CellValues,
    cell_info: &BTreeMap<String, (String, CellInfo, usize)>,
    context: &mut ICContext,
) -> Result<(), plonk::Error> {
    for i in config.gates.len()..config.algos.len() {
        let algo = &config.algos[i][0];

        if algo.name.trim() == algo_type {
            let (_operand, _scalar) = algo.compute(
                layouter,
                ecc_chip,
                config,
                gate_states,
                operands,
                cell_values,
                cell_info,
                context,
            )?;

            let constraint_name = algo.items[algo.items.len() - 1].1.name.clone(); //name fromt the last item
            let (constraint_name, instance_name_y, is_two) =
                if config.instance_info.contains_key(&constraint_name) {
                    (constraint_name, "".to_string(), false)
                } else {
                    let instance_name_x = constraint_name.clone() + SIGN_OF_X;
                    if config.instance_info.contains_key(&instance_name_x) {
                        (instance_name_x, constraint_name + SIGN_OF_Y, true)
                    } else {
                        (constraint_name, "".to_string(), false)
                    }
                };

            if config.instance_info.contains_key(&constraint_name) {
                match _operand {
                    Operand::Point(point) => {
                        if is_two {
                            halo2api::constrain_instance(
                                layouter,
                                &point.clone().unwrap().inner().x().cell(),
                                &config.primary,
                                config.instance_info[&constraint_name],
                                (context.0, &constraint_name),
                            )?;
                            halo2api::constrain_instance(
                                layouter,
                                &point.unwrap().inner().y().cell(),
                                &config.primary,
                                config.instance_info[&instance_name_y],
                                (context.0, &instance_name_y),
                            )?;
                        } else {
                            halo2api::constrain_instance(
                                layouter,
                                &point.unwrap().extract_p().inner().cell(),
                                &config.primary,
                                config.instance_info[&constraint_name],
                                (context.0, &constraint_name),
                            )?;
                        }
                    }
                    Operand::Cell(cell) => {
                        halo2api::constrain_instance(
                            layouter,
                            &cell.unwrap().cell(),
                            &config.primary,
                            config.instance_info[&constraint_name],
                            (context.0, &constraint_name),
                        )?;
                    }
                    _ => {}
                }
            } else if context.2.contains_key(&constraint_name) {
                let constraint_points = &context.2;

                match _operand {
                    Operand::Point(Some(point)) => {
                        let desc = format!("witness [{}]", constraint_name);

                        let p = halo2_gadgets::ecc::NonIdentityPoint::new(
                            ecc_chip.clone(),
                            layouter.namespace(|| &desc),
                            constraint_points[&constraint_name].map(|p| p.to_affine()),
                        )?;

                        let desc = &format!("[{}] equality", constraint_name);
                        point.constrain_equal(layouter.namespace(|| desc), &p)?;

                        #[cfg(feature = "debug")]
                        if context.0.is_some() {
                            context
                                .0
                                .as_mut()
                                .unwrap()
                                .entry("constrain_equal".to_string())
                                .or_insert(Vec::new())
                                .push(format!("{}", constraint_name));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
