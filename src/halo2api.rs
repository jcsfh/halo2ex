use pasta_curves::pallas;

use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region},
    plonk::{self, Advice, Assigned, Column, Error, Instance as InstanceColumn},
};

use halo2_gadgets::utilities::UtilitiesInstructions;

use std::collections::BTreeMap;

pub(crate) fn load_private(
    instructions: &impl UtilitiesInstructions<
        pallas::Base,
        Var = AssignedCell<pallas::Base, pallas::Base>,
    >,
    layouter: &mut impl Layouter<pallas::Base>,
    namespace: &str,
    columns: &[Column<Advice>],
    col: usize,
    value: &Option<pallas::Base>,
    _debug_info: (&mut Option<BTreeMap<String, Vec<String>>>, &str),
) -> Result<AssignedCell<pallas::Base, pallas::Base>, plonk::Error> {
    let ret = instructions.load_private(
        layouter.namespace(|| namespace),
        columns[col],
        value.clone(),
    )?;

    #[cfg(feature = "debug")]
    if _debug_info.0.is_some() {
        _debug_info
            .0
            .as_mut()
            .unwrap()
            .entry("load_private".to_string())
            .or_insert(Vec::new())
            .push(format!("{}[{}]", _debug_info.1, col));
    }
    Ok(ret)
}

pub(crate) fn copy_advice<A, AR>(
    cell: &AssignedCell<pallas::Base, pallas::Base>,
    region: &mut Region<'_, pallas::Base>,
    annotation: A,
    columns: &[Column<Advice>],
    col: usize,
    offset: usize,
    _debug_info: (&mut Option<BTreeMap<String, Vec<String>>>, &str),
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error>
where
    A: Fn() -> AR,
    AR: Into<String>,
{
    let ret = cell.copy_advice(annotation, region, columns[col], offset)?;

    #[cfg(feature = "debug")]
    if _debug_info.0.is_some() {
        _debug_info
            .0
            .as_mut()
            .unwrap()
            .entry("copy_advice".to_string())
            .or_insert(Vec::new())
            .push(format!("{}[{}][{}]", _debug_info.1, col, offset));
    }
    Ok(ret)
}

pub(crate) fn assign_advice<'v, V, A, AR>(
    region: &mut Region<'_, pallas::Base>,
    annotation: A,
    columns: &[Column<Advice>],
    col: usize,
    offset: usize,
    to: V,
    _debug_info: (&mut Option<BTreeMap<String, Vec<String>>>, &str),
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error>
where
    V: FnMut() -> Result<pallas::Base, Error> + 'v,
    for<'vr> Assigned<pallas::Base>: From<&'vr pallas::Base>,
    A: Fn() -> AR,
    AR: Into<String>,
{
    let ret = region.assign_advice(annotation, columns[col], offset, to)?;

    #[cfg(feature = "debug")]
    if _debug_info.0.is_some() {
        _debug_info
            .0
            .as_mut()
            .unwrap()
            .entry("assign_advice".to_string())
            .or_insert(Vec::new())
            .push(format!("{}[{}][{}]", _debug_info.1, col, offset));
    }
    Ok(ret)
}

pub(crate) fn assign_advice_from_instance<A, AR>(
    region: &mut Region<'_, pallas::Base>,
    annotation: A,
    instance: &Column<InstanceColumn>,
    row: usize,
    columns: &[Column<Advice>],
    col: usize,
    offset: usize,
    _debug_info: (&mut Option<BTreeMap<String, Vec<String>>>, &str),
) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error>
where
    A: Fn() -> AR,
    AR: Into<String>,
{
    let ret =
        region.assign_advice_from_instance(annotation, *instance, row, columns[col], offset)?;

    #[cfg(feature = "debug")]
    if _debug_info.0.is_some() {
        _debug_info
            .0
            .as_mut()
            .unwrap()
            .entry("assign_advice_from_instance".to_string())
            .or_insert(Vec::new())
            .push(format!(
                "{}[{}][{}] == instances[{}]",
                _debug_info.1, col, offset, row
            ));
    }
    Ok(ret)
}

pub(crate) fn constrain_instance(
    layouter: &mut impl Layouter<pallas::Base>,
    cell: &Cell,
    instance: &Column<InstanceColumn>,
    row: usize,
    _debug_info: (&mut Option<BTreeMap<String, Vec<String>>>, &str),
) -> Result<(), Error> {
    let ret = layouter.constrain_instance(*cell, *instance, row)?;

    #[cfg(feature = "debug")]
    if _debug_info.0.is_some() {
        _debug_info
            .0
            .as_mut()
            .unwrap()
            .entry("constrain_instance".to_string())
            .or_insert(Vec::new())
            .push(format!("{} == instances[{}]", _debug_info.1, row));
    }
    Ok(ret)
}

#[cfg(feature = "debug")]
pub(crate) fn output_debug_info(name: &str, _debug_info: &Option<BTreeMap<String, Vec<String>>>) {
    use std::io::Write;

    if _debug_info.is_some() {
        let error_info = "output_debug_info write error";
        let mut f = std::fs::File::create(&format!("{}.txt", name))
            .expect("output_debug_info create error");

        f.write(format!("[{}] {{\r\n", name).as_bytes())
            .expect(error_info);
        for (name, info) in _debug_info.as_ref().unwrap() {
            f.write(format!("    {} => (\r\n", name).as_bytes())
                .expect(error_info);
            for item in info {
                f.write(format!("        {}\r\n", item).as_bytes())
                    .expect(error_info);
            }
            f.write("    )\r\n".as_bytes()).expect(error_info);
        }
        f.write("}\r\n\r\n".as_bytes()).expect(error_info);
    }
}
