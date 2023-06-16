use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{self, Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use pasta_curves::{arithmetic::FieldExt, pallas};

use halo2_gadgets::{
    ecc::{chip::EccChip, Point, X},
    primitives::sinsemilla::K,
    sinsemilla::{
        chip::{SinsemillaChip, SinsemillaConfig},
        CommitDomain, Message, MessagePiece,
    },
    utilities::{bitrange_subset, bool_check},
};

use lazy_static::lazy_static;
use std::collections::{BTreeMap, HashMap};

use crate::base;
use crate::consts::*;
use crate::domains::*;
use crate::halo2api;
use crate::types::*;

pub(crate) const MAX_PIECE_WIDTH: usize = 250;
pub(crate) const MAX_CANON_OFFSET: usize = 64;
const SLICE_SEP: &str = "_";

pub(crate) type GSinsemillaConfig =
    SinsemillaConfig<BaseHashDomains, HashDomainsType, DomainFixedBases>;
pub(crate) type InputConfigMap = BTreeMap<
    String, //name of input
    (
        Option<AssignedCell<pallas::Base, pallas::Base>>, // x-coordinate
        Option<AssignedCell<pallas::Base, pallas::Base>>, //option for y-coordinate
        usize,                                            // width of the input
    ),
>;

// name, host name, start, width, cell type.
pub(crate) type RuleData = BTreeMap<String, (String, usize, usize, CellType)>;

#[derive(Clone, Debug, Default)]
struct CompositionRule {
    slices: RuleData,
}

/// The values of the running sum at the start and end of the range being used for a
/// canonicity check.
type CanonicityBounds = (
    AssignedCell<pallas::Base, pallas::Base>,
    AssignedCell<pallas::Base, pallas::Base>,
);

#[derive(Debug)]
pub(crate) enum PointResult {
    X(Option<X<pallas::Affine, EccChip<DomainFixedBases>>>),
    Point(Option<Point<pallas::Affine, EccChip<DomainFixedBases>>>),
}

lazy_static! {
    static ref VEC_TWO_POW: Vec<pallas::Base> = {
        let mut vec: Vec<pallas::Base> = Vec::new();
        for i in 0..128 {
            vec.push(pallas::Base::from_u128(1 << i));
        }
        let two = pallas::Base::from(2);
        for _ in 128..FILED_SIZE {
            vec.push(vec.last().unwrap() * two);
        }
        vec
    };
}

#[derive(Clone, Debug)]
pub struct CommitConfig {
    pub(crate) qs: Vec<Selector>,
    pub(crate) advices: [Column<Advice>; 10],
    pub(crate) sinsemilla_config: GSinsemillaConfig,

    pub(crate) commit_domain: HashDomainsType,
    pub(crate) gates: Vec<GateInfo>,

    // composition rules
    composition_rules: CompositionRule,
}

impl CommitConfig {
    fn is_slice_name(name: &String) -> bool {
        name.find(SLICE_SEP).is_some()
    }

    fn extract_piece_name(name: &String) -> String {
        let mut ret = name.clone();
        let index = ret.find(SLICE_SEP);
        if index.is_some() {
            ret.truncate(index.unwrap());
        }
        ret
    }

    fn check_if_same_pieces(pieces: &Vec<String>) -> bool {
        if pieces.len() > 1 {
            let name = Self::extract_piece_name(&pieces[0]);
            for i in 1..pieces.len() {
                if name != Self::extract_piece_name(&pieces[i]) {
                    return false;
                }
            }
        }
        return true;
    }

    fn create_gate(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: &[Column<Advice>; 10],
        q: &Selector,
        gate: &GateInfo,
        slices: &mut BTreeMap<String, CellType>,
        pad_slices: &mut RuleData,
    ) -> CompositionRule {
        // generate rule
        let mut rule = CompositionRule::default();
        if !CellType::is_input_cell(gate.cells[0].celltype) {
            let mut _slices = gate.cells[1..]
                .iter()
                .map(|cell| {
                    assert!(
                        !slices.contains_key(&cell.name),
                        "[Sinsemilla] cell name [{}] duplicated",
                        cell.name
                    );

                    if cell.celltype == CellType::PadSlice {
                        pad_slices.insert(
                            cell.name.clone(),
                            (String::new(), 0, cell.width, cell.celltype),
                        );
                    }

                    (cell.name.clone(), cell.celltype)
                })
                .collect::<BTreeMap<_, _>>();
            slices.append(&mut _slices);
        } else {
            let mut offset: usize = 0;
            rule.slices = gate.cells[1..]
                .iter()
                .filter_map(|cell| {
                    let rule = if CellType::is_piece_or_slice_cell(cell.celltype)
                        || cell.celltype == CellType::YSlice
                    {
                        assert!(
                            cell.width <= MAX_PIECE_WIDTH,
                            "[Sinsemilla] [{}]: width[{}] must not be greater than [{}]",
                            cell.name,
                            cell.width,
                            MAX_PIECE_WIDTH
                        );
                        assert!(
                            cell.celltype != CellType::TopSlice,
                            "[Sinsemilla] [{}]: TopSlice should Not be in the Input configuration",
                            cell.name
                        );

                        let mut _celltype;
                        if slices.contains_key(&cell.name) {
                            _celltype = slices[&cell.name];
                        } else {
                            _celltype = cell.celltype;
                        }

                        Some((
                            cell.name.clone(),
                            (gate.cells[0].name.clone(), offset, cell.width, _celltype),
                        ))
                    } else {
                        None
                    };
                    offset += cell.width;
                    rule
                })
                .collect::<BTreeMap<_, _>>();
        }

        // create gates
        meta.create_gate(base::string_to_static_str(&gate.name), |meta| {
            let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

            let q = meta.query_selector(*q);
            let mut desc;
            let mut constraints = Vec::new();

            // query values
            let values = gate
                .cells
                .iter()
                .filter_map(|cell| {
                    if cell.celltype != CellType::YSlice && cell.celltype != CellType::PadSlice {
                        let rotation = match cell.row {
                            RowType::Cur => Rotation::cur(),
                            RowType::Next => Rotation::next(),
                            RowType::Prev => Rotation::prev(),
                        };

                        let value = match cell.coltype {
                            ColType::Advice => meta.query_advice(advices[cell.col], rotation),
                            _ => {
                                panic!("create_gate: not supported cell type: [{:?}]", cell.coltype)
                            }
                        };

                        Some((Some(value), cell.name.clone(), cell.celltype, cell.width))
                    } else {
                        Some((None, cell.name.clone(), cell.celltype, cell.width))
                    }
                })
                .collect::<Vec<_>>();

            let value_len = values.len();
            assert_eq!(
                value_len,
                gate.cells.len(),
                "[Sinsemilla] [{}]: wrong value_len: {} != {}",
                gate.cells[0].name,
                value_len,
                gate.cells.len()
            );

            // create constraints
            let mut offset: usize = 0;
            let mut top_bit_value: Option<Expression<pallas::Base>> = None;
            let mut prime: Option<Expression<pallas::Base>> = None;
            let mut whole = Expression::Constant(pallas::Base::zero());
            let mut whole_prime_check = Expression::Constant(pallas::Base::zero());
            let mut whole_items = Vec::new();

            // canonicity check and whole value computation
            for i in 1..value_len {
                let (_value, _name, mut _celltype, _width) = &values[i];
                if _celltype == CellType::YSlice {
                    continue;
                }

                if _celltype != CellType::PadSlice {
                    let _value = _value.as_ref().unwrap();

                    // update celltype like TopSlice
                    if slices.contains_key(_name) {
                        _celltype = slices[_name];
                    }
                    let _celltype = &_celltype;

                    match *_celltype {
                        CellType::PrimeCheck => prime = Some(_value.clone()),
                        CellType::CanonicityCheck | CellType::CanonicityCheckSlice => {
                            desc = format!("[Sinsemilla] canonicity_check [{}]", gate.cells[i].name);
                            constraints.push((base::string_to_static_str(&desc), _value.clone()));
                        }
                        _ => {}
                    }

                    if CellType::is_piece_or_slice_cell(*_celltype) {
                        whole = whole + _value.clone() * VEC_TWO_POW[offset];

                        if CellType::is_input_cell(gate.cells[0].celltype)
                            && offset < FILED_SIZE - 1
                        {
                            if whole_items.len() < 2 && offset != MAX_PIECE_WIDTH {
                                whole_items.push(_name.clone());
                                whole_prime_check = whole.clone();
                            }
                        }
                    }

                    if offset == FILED_SIZE - 1 {
                        assert!(
                            *_celltype == CellType::TopSlice,
                            "[Sinsemilla] cell type[{:?}] of [{}] should be configured TopSlice in piece gate",
                            _celltype,
                            _name
                        );
                        top_bit_value = Some(_value.clone());
                    }
                }
                if offset < gate.cells[0].width {
                    offset += gate.cells[i].width;
                }
            }
            assert_eq!(
                offset, gate.cells[0].width,
                "[Sinsemilla] [{}]: wrong accumulated width: {} != {}",
                gate.cells[0].name, offset, gate.cells[0].width
            );

            if constraints.len() > 0 {
                assert!(
                    top_bit_value.is_some(),
                    "[Sinsemilla] [{}]: top_bit_value is none",
                    gate.cells[0].name,
                );
                constraints = constraints
                    .iter()
                    .map(move |(desc, poly)| {
                        (desc.clone(), top_bit_value.clone().unwrap() * poly.clone())
                    })
                    .collect();
            }

            // decomposition check
            let decomposition_check = values[0].0.as_ref().unwrap().clone() - whole;
            desc = format!("[Sinsemilla] decomposition [{}]", gate.name);
            constraints.push((base::string_to_static_str(&desc), decomposition_check));

            // bool check
            for i in 0..gate.cells.len() {
                if values[i].0.is_some() {
                    let cell = &gate.cells[i];
                    if cell.width == 1 {
                        desc = format!("[Sinsemilla] bool_check [{}]", cell.name);
                        constraints.push((
                            base::string_to_static_str(&desc),
                            bool_check(values[i].0.as_ref().unwrap().clone()),
                        ));
                    }
                }
            }

            // prime checks: < 2^254 + 2^126
            if CellType::is_input_cell(gate.cells[0].celltype) && gate.cells[0].width >= FILED_SIZE
            {
                assert!(prime.is_some(), "[Sinsemilla] [{}]: prime is none", gate.cells[0].name,);

                let mut n: usize = 130;
                if whole_items.len() > 1 {
                    if !Self::check_if_same_pieces(&whole_items) {
                        n = 140;
                    }
                }

                let prime_check =
                    whole_prime_check + Expression::Constant(VEC_TWO_POW[n]) - t_p - prime.unwrap();

                desc = format!("[Sinsemilla] prime_check [{}]", gate.cells[0].name);
                constraints.push((base::string_to_static_str(&desc), prime_check));
            }

            constraints
                .iter()
                .map(move |(desc, poly)| (desc.clone(), q.clone() * poly.clone()))
                .collect::<Vec<_>>()
                .into_iter()
        });

        rule
    }

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: [Column<Advice>; 10],
        sinsemilla_config: GSinsemillaConfig,
        commit_domain: HashDomainsType,
        gates: &Vec<GateInfo>,
    ) -> Self {
        let mut composition_rules: CompositionRule = Default::default();

        let mut slices = BTreeMap::new();
        let mut pad_slices = BTreeMap::new();
        let mut first_celltype = CellType::Slice;
        let mut last_celltype = CellType::Slice;

        let mut y_checks = false;

        let mut qs = gates
            .iter()
            .enumerate()
            .map(|(i, gate)| {
                assert!(
                    CellType::is_input_cell(gate.cells[0].celltype)
                        || gate.cells[0].celltype == CellType::Piece,
                    "[Sinsemilla] [{}]: the first cell should be Input or Piece. configured celltype: [{:?}]",
                    gate.cells[0].name,
                    gate.cells[0].celltype
                );
                assert!(
                    gate.cells[1].width == MAX_PIECE_WIDTH
                        || (gate.cells[1].width < MAX_CANON_OFFSET
                            && CellType::is_input_cell(gate.cells[0].celltype))
                        || !CellType::is_input_cell(gate.cells[0].celltype),
                    "[Sinsemilla] [{}]: width not satisfied. celltype: [{:?}], width: [{}]",
                    gate.cells[0].name,
                    gate.cells[0].celltype,
                    gate.cells[1].width
                );

                let q = meta.selector();
                let mut rule =
                    Self::create_gate(meta, &advices, &q, &gate, &mut slices, &mut pad_slices);
                if rule.slices.len() > 0 {
                    composition_rules.slices.append(&mut rule.slices);
                }

                if !y_checks {
                    for cell in &gate.cells {
                        if cell.celltype == CellType::YSlice {
                            y_checks = true;
                        }
                    }
                }

                if i == 0 {
                    first_celltype = gate.cells[0].celltype;
                }
                last_celltype = gate.cells[0].celltype;

                q
            })
            .collect::<Vec<_>>();

        assert!(
            first_celltype == CellType::Piece || first_celltype == last_celltype,
            "[Sinsemilla] the first gate cell type configured is supposed to be Piece, not Input or YInput"
        );
        assert!(
            CellType::is_input_cell(last_celltype),
            "[Sinsemilla] the last gate cell type configured must be Input or YInput"
        );

        // find out pad slice, should be only one pad slice
        if pad_slices.len() > 0 {
            composition_rules.slices.append(&mut pad_slices);
        }

        if y_checks {
            let q = Self::configure_y_checks(meta, &advices);
            qs.push(q);
        }

        let config = Self {
            qs,
            advices,
            sinsemilla_config,
            gates: gates.clone(),
            commit_domain,
            composition_rules,
        };

        config
    }
    // from zcash
    fn configure_y_checks(
        meta: &mut ConstraintSystem<pallas::Base>,
        advices: &[Column<Advice>; 10],
    ) -> Selector {
        /*
            Assign y canonicity gate in the following configuration:
                | A_5 | A_6 |  A_7  |   A_8   |     A_9     |
                ---------------------------------------------
                |  y  | lsb |  k_0  |   k_2   |     k_3     |
                |  j  | z1_j| z13_j | j_prime | z13_j_prime |
            where z1_j = k_1.
        */

        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));

        let q_y_canon = meta.selector();

        meta.create_gate("[Sinsemilla] y coordinate checks", |meta| {
            let q_y_canon = meta.query_selector(q_y_canon);
            let y = meta.query_advice(advices[5], Rotation::cur());
            // LSB has been boolean-constrained outside this gate.
            let lsb = meta.query_advice(advices[6], Rotation::cur());
            // k_0 has been constrained to 9 bits outside this gate.
            let k_0 = meta.query_advice(advices[7], Rotation::cur());
            // k_1 = z1_j (witnessed in the next rotation).
            // k_2 has been constrained to 4 bits outside this gate.
            let k_2 = meta.query_advice(advices[8], Rotation::cur());
            // This gate constrains k_3 to be boolean.
            let k_3 = meta.query_advice(advices[9], Rotation::cur());

            // j = LSB + (2)k_0 + (2^10)k_1
            let j = meta.query_advice(advices[5], Rotation::next());
            let z1_j = meta.query_advice(advices[6], Rotation::next());
            let z13_j = meta.query_advice(advices[7], Rotation::next());

            // j_prime = j + 2^130 - t_P
            let j_prime = meta.query_advice(advices[8], Rotation::next());
            let z13_j_prime = meta.query_advice(advices[9], Rotation::next());

            // Decomposition checks
            let decomposition_checks = {
                // Check that k_3 is boolean
                let k3_check = bool_check(k_3.clone());
                // Check that j = LSB + (2)k_0 + (2^10)k_1
                let k_1 = z1_j;
                let j_check = j.clone()
                    - (lsb
                        + k_0 * Expression::Constant(VEC_TWO_POW[1])
                        + k_1 * Expression::Constant(VEC_TWO_POW[10]));
                // Check that y = j + (2^250)k_2 + (2^254)k_3
                let y_check = y
                    - (j.clone()
                        + k_2.clone() * Expression::Constant(VEC_TWO_POW[250])
                        + k_3.clone() * Expression::Constant(VEC_TWO_POW[254]));
                // Check that j_prime = j + 2^130 - t_P
                let j_prime_check =
                    j + Expression::Constant(VEC_TWO_POW[130]) - t_p.clone() - j_prime;

                std::iter::empty()
                    .chain(Some(("k3_check", k3_check)))
                    .chain(Some(("j_check", j_check)))
                    .chain(Some(("y_check", y_check)))
                    .chain(Some(("j_prime_check", j_prime_check)))
            };

            // Canonicity checks. These are enforced if and only if k_3 = 1.
            let canonicity_checks = {
                std::iter::empty()
                    .chain(Some(("k_3 = 1 => k_2 = 0", k_2)))
                    .chain(Some(("k_3 = 1 => z13_j = 0", z13_j)))
                    .chain(Some(("k_3 = 1 => z13_j_prime = 0", z13_j_prime)))
                    .map(move |(name, poly)| (name, k_3.clone() * poly))
            };

            decomposition_checks
                .chain(canonicity_checks)
                .map(move |(name, poly)| (name, q_y_canon.clone() * poly))
        });

        q_y_canon
    }

    fn canon_bitshift_130(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        a: AssignedCell<pallas::Base, pallas::Base>,
        _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
    ) -> Result<CanonicityBounds, Error> {
        // Decompose the low 130 bits of a_prime = a + 2^130 - t_P, and output
        // the running sum at the end of it. If a_prime < 2^130, the running sum
        // will be 0.
        let a_prime = a.value().map(|a| {
            let t_p = pallas::Base::from_u128(T_P);
            a + VEC_TWO_POW[130] - t_p
        });
        let zs = self.sinsemilla_config.lookup_config().witness_check(
            layouter.namespace(|| "[Sinsemilla] Decompose low 130 bits of (a + 2^130 - t_P)"),
            a_prime,
            13,
            false,
        )?;
        assert_eq_synthesize_error!(zs.len(), 14, "[Sinsemilla] canon_bitshift_130"); // [z_0, z_1, ..., z_13]

        Ok((zs[0].clone(), zs[13].clone()))
    }

    fn canon_bitshift_n(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        n: usize, // could be 130 or 140
        a0: AssignedCell<pallas::Base, pallas::Base>,
        a0_width: usize,
        b: AssignedCell<pallas::Base, pallas::Base>,
        _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
    ) -> Result<CanonicityBounds, Error> {
        // Decompose the low n bits of prime = a0 + 2^offset b + 2^n - t_P,
        // and output the running sum at the end of it.
        // If a0_b_prime < 2^n, the running sum will be 0.
        let a0_b_prime = a0.value().zip(b.value()).map(|(a0, b)| {
            let t_p = pallas::Base::from_u128(T_P);
            a0 + (VEC_TWO_POW[a0_width] * b) + VEC_TWO_POW[n] - t_p
        });

        let desc = format!(
            "[Sinsemilla] Decompose low [{}] bits of the canonicity inputs",
            n
        );
        let zs = self.sinsemilla_config.lookup_config().witness_check(
            layouter.namespace(|| desc),
            a0_b_prime,
            n / K,
            false,
        )?;
        assert_eq_synthesize_error!(
            zs.len(),
            n / K + 1,
            &format!("[Sinsemilla] canon_bitshift_n: n[{}], K[{}]", n, K)
        ); // [z_0, z_1, ..., z_13 or z_14]

        Ok((zs[0].clone(), zs[n / K].clone()))
    }

    // from zcash
    // Check canonicity of y-coordinate given its LSB as a value.
    // Also, witness the LSB and return the witnessed cell.
    fn y_canonicity(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        y: AssignedCell<pallas::Base, pallas::Base>,
        lsb: Option<pallas::Base>,
        _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Decompose the field piece
        //      y = LSB || k_0 || k_1 || k_2 || k_3
        //        = (bit 0) || (bits 1..=9) || (bits 10..=249) || (bits 250..=253) || (bit 254)
        let (k_0, k_1, k_2, k_3) = {
            let k_0 = y.value().map(|y| bitrange_subset(y, 1..10));
            let k_1 = y.value().map(|y| bitrange_subset(y, 10..250));
            let k_2 = y.value().map(|y| bitrange_subset(y, 250..254));
            let k_3 = y.value().map(|y| bitrange_subset(y, 254..255));

            (k_0, k_1, k_2, k_3)
        };

        // Range-constrain k_0 to be 9 bits.
        let k_0 = self.sinsemilla_config.lookup_config().witness_short_check(
            layouter.namespace(|| "[Sinsemilla] Constrain k_0 to be 9 bits"),
            k_0,
            9,
        )?;

        // Range-constrain k_2 to be 4 bits.
        let k_2 = self.sinsemilla_config.lookup_config().witness_short_check(
            layouter.namespace(|| "[Sinsemilla] Constrain k_2 to be 4 bits"),
            k_2,
            4,
        )?;

        // Decompose j = LSB + (2)k_0 + (2^10)k_1 using 25 ten-bit lookups.
        let (j, z1_j, z13_j) = {
            let j = lsb.zip(k_0.value()).zip(k_1).map(|((lsb, k_0), k_1)| {
                let two = pallas::Base::from(2);
                let two_pow_10 = pallas::Base::from(1 << 10);
                lsb + two * k_0 + two_pow_10 * k_1
            });
            let zs = self.sinsemilla_config.lookup_config().witness_check(
                layouter.namespace(|| "[Sinsemilla] Decompose j = LSB + (2)k_0 + (2^10)k_1"),
                j,
                25,
                true,
            )?;
            (zs[0].clone(), zs[1].clone(), zs[13].clone())
        };

        // Decompose j_prime = j + 2^130 - t_P using 13 ten-bit lookups.
        // We can reuse the canon_bitshift_130 logic here.
        let (j_prime, z13_j_prime) = self.canon_bitshift_130(
            layouter.namespace(|| "j_prime = j + 2^130 - t_P"),
            j.clone(),
            _debug_info,
        )?;

        /*
            Assign y canonicity gate in the following configuration:
                | A_5 | A_6 |  A_7  |   A_8   |     A_9     |
                ---------------------------------------------
                |  y  | lsb |  k_0  |   k_2   |     k_3     |
                |  j  | z1_j| z13_j | j_prime | z13_j_prime |
            where z1_j = k_1.
        */
        layouter.assign_region(
            || "[Sinsemilla] y canonicity",
            |mut region| {
                self.qs[self.qs.len() - 1].enable(&mut region, 0)?;

                // Offset 0
                let lsb = {
                    let offset = 0;

                    // Copy y.
                    halo2api::copy_advice(
                        &y,
                        &mut region,
                        || "[Sinsemilla] copy y",
                        &self.advices,
                        5,
                        offset,
                        (_debug_info, "y_canonicity"),
                    )?;
                    // Witness LSB.
                    let lsb = halo2api::assign_advice(
                        &mut region,
                        || "[Sinsemilla] witness LSB",
                        &self.advices,
                        6,
                        offset,
                        || lsb.ok_or(Error::Synthesis),
                        (_debug_info, "y_lsb"),
                    )?;
                    // Witness k_0.
                    halo2api::copy_advice(
                        &k_0,
                        &mut region,
                        || "[Sinsemilla] copy k_0",
                        &self.advices,
                        7,
                        offset,
                        (_debug_info, "k_0"),
                    )?;
                    //k_0.copy_advice(|| "copy k_0", &mut region, self.advices[7], offset)?;
                    // Copy k_2.
                    halo2api::copy_advice(
                        &k_2,
                        &mut region,
                        || "[Sinsemilla] copy k_2",
                        &self.advices,
                        8,
                        offset,
                        (_debug_info, "k_2"),
                    )?;
                    //k_2.copy_advice(|| "copy k_2", &mut region, self.advices[8], offset)?;
                    // Witness k_3.
                    halo2api::assign_advice(
                        &mut region,
                        || "[Sinsemilla] witness k_3",
                        &self.advices,
                        9,
                        offset,
                        || k_3.ok_or(Error::Synthesis),
                        (_debug_info, "k_3"),
                    )?;

                    lsb
                };

                // Offset 1
                {
                    let offset = 1;

                    // Copy j.
                    halo2api::copy_advice(
                        &j,
                        &mut region,
                        || "[Sinsemilla] copy j",
                        &self.advices,
                        5,
                        offset,
                        (_debug_info, "j"),
                    )?;
                    //j.copy_advice(|| "copy j", &mut region, self.advices[5], offset)?;
                    // Copy z1_j.
                    halo2api::copy_advice(
                        &z1_j,
                        &mut region,
                        || "[Sinsemilla] copy z1_j",
                        &self.advices,
                        6,
                        offset,
                        (_debug_info, "z1_j"),
                    )?;
                    //z1_j.copy_advice(|| "copy z1_j", &mut region, self.advices[6], offset)?;
                    // Copy z13_j.
                    halo2api::copy_advice(
                        &z13_j,
                        &mut region,
                        || "[Sinsemilla] copy z13_j",
                        &self.advices,
                        7,
                        offset,
                        (_debug_info, "z13_j"),
                    )?;
                    //z13_j.copy_advice(|| "copy z13_j", &mut region, self.advices[7], offset)?;
                    // Copy j_prime.
                    halo2api::copy_advice(
                        &j_prime,
                        &mut region,
                        || "[Sinsemilla] copy j_prime",
                        &self.advices,
                        8,
                        offset,
                        (_debug_info, "j_prime"),
                    )?;
                    //j_prime.copy_advice(|| "copy j_prime", &mut region, self.advices[8], offset)?;
                    // Copy z13_j_prime.
                    halo2api::copy_advice(
                        &z13_j_prime,
                        &mut region,
                        || "[Sinsemilla] copy z13_j_prime",
                        &self.advices,
                        9,
                        offset,
                        (_debug_info, "z13_j_prime"),
                    )?;
                }

                Ok(lsb)
            },
        )
    }

    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign_region(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        chip: SinsemillaChip<BaseHashDomains, HashDomainsType, DomainFixedBases>,
        ecc_chip: EccChip<DomainFixedBases>,
        inputs: &InputConfigMap,
        r: Option<pallas::Scalar>,
        is_short_commit: bool,
        is_with_witnesses: bool,
        _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
    ) -> Result<PointResult, Error> {
        let input_gates = self
            .gates
            .iter()
            .filter(|gate| CellType::is_input_cell(gate.cells[0].celltype))
            .collect::<Vec<_>>();

        let mut prime_cells = HashMap::new();
        let mut z13s: BTreeMap<String, (usize, Option<AssignedCell<pallas::Base, pallas::Base>>)> =
            BTreeMap::new();
        for gate in &self.gates {
            for cell in &gate.cells {
                if cell.celltype == CellType::CanonicityCheck
                    || cell.celltype == CellType::PrimeCheck
                {
                    prime_cells.insert(cell.name.clone(), true);
                }

                // record z13 items, but no value here (value will be filled from zs below)
                if CellType::is_z13_cell(cell.celltype) {
                    z13s.insert(cell.name.clone(), (0, None));
                }
            }
        }

        let mut desc: String;
        let mut pieces = BTreeMap::new();
        let mut piece_slices: BTreeMap<
            String,
            (
                usize, //width of an slice
                Vec<(
                    usize, //offset
                    usize, //width
                    Option<pallas::Base>,
                    Option<AssignedCell<pallas::Base, pallas::Base>>,
                )>,
            ),
        > = BTreeMap::new();
        let mut ylsbs = HashMap::new();
        let mut z1_items = Vec::new();

        // collect slice value to corresponding piece
        for (slice_name, rule) in &self.composition_rules.slices {
            let (_hname, _start, _width, _celltype) = &rule;
            let name = Self::extract_piece_name(&slice_name);
            let values = piece_slices.entry(name.clone()).or_insert((0, Vec::new()));

            if *_celltype == CellType::PadSlice {
                (*values).0 += *_width;
                continue;
            }

            let v = inputs.get(_hname);
            assert_synthesize_error!(
                v.is_some(),
                format!(
                    "[Sinsemilla] [{}] not in inputs[{:?}]",
                    _hname,
                    inputs.keys()
                )
            );
            let (x, y, _input_width) = v.unwrap();
            let end = *_start + *_width;
            assert_synthesize_error!(
                end <= *_input_width + 1,
                &format!(
                    "[Sinsemilla] assert failed: [{}] <= [{}] + 1",
                    end, _input_width
                )
            );

            let v = if end <= *_input_width {
                x.as_ref()
                    .unwrap()
                    .value()
                    .map(|x| bitrange_subset(x, *_start..end))
            } else {
                y.as_ref()
                    .unwrap()
                    .value()
                    .map(|y| bitrange_subset(y, 0..1))
            };

            // Constrain width bits.
            desc = format!(
                "[Sinsemilla] [{}] is [{}] bits",
                slice_name.clone(),
                *_width
            );
            if *_width <= K {
                let v_assignedcell = self.sinsemilla_config.lookup_config().witness_short_check(
                    layouter.namespace(|| desc),
                    v,
                    *_width,
                )?;

                (*values)
                    .1
                    .push((*_start, *_width, None, Some(v_assignedcell.clone())));
                pieces.insert(slice_name.clone(), Some(v_assignedcell));
            } else {
                (*values).1.push((*_start, *_width, v, None));

                if Self::is_slice_name(slice_name) {
                    // this slice must be equal to z1, collect here for the slice order
                    pieces.insert(slice_name.clone(), None);
                    // collect z1 item
                    z1_items.push(slice_name.clone());
                }
            }
            (*values).0 += *_width; // calculate total width

            let (_total_width, _slices) = &values;

            // y_lsb
            //if y.is_some() && *_start >= FILED_SIZE && *_width == 1 {
            if *_start >= FILED_SIZE && *_width == 1 {
                ylsbs.insert(_hname.clone(), (name.clone(), (*_slices).len() - 1));
            }
        }

        let mut z1_info = BTreeMap::new();
        let mut primes = BTreeMap::new();
        let mut message_pieces = Vec::new();

        for (index, (name, values)) in piece_slices.iter_mut().enumerate() {
            let total_width = values.0;

            if values.1.len() > 1 {
                let mut whole_value = pallas::Base::zero();
                if is_with_witnesses {
                    let mut offset: usize = 0;
                    for value in &values.1 {
                        let (_start, _width, _v_base, _v_assignedcell) = value;

                        if _v_base.is_some() {
                            whole_value += _v_base.unwrap() * VEC_TWO_POW[offset];
                        } else {
                            whole_value += _v_assignedcell.as_ref().unwrap().value().unwrap()
                                * VEC_TWO_POW[offset];
                        }
                        offset += *_width;
                    }
                }

                values.1[0].2 = Some(whole_value); // pallas::Base
                values.1[0].3 = None; // AssignedCell
            }

            assert_eq_synthesize_error!(
                (total_width / K) * K,
                total_width,
                &format!(
                    "[Sinsemilla] [{}]: [{}] is not times of K[{}]",
                    name, total_width, K
                )
            );

            let whole = MessagePiece::from_field_elem(
                chip.clone(),
                layouter.namespace(|| name),
                values.1[0].2,
                total_width / K,
            );
            assert_synthesize_error!(
                whole.is_ok(),
                &format!("[Sinsemilla] [{}]: failed to create MessagePiece", name)
            );
            let whole = whole.unwrap();

            // collect z1 item info on message order
            z1_info.insert(name.clone(), (index, total_width));

            if total_width == MAX_PIECE_WIDTH {
                // collect prime data for 130 bits constrait
                if values.1[0].0 == 0 {
                    // must constrait to 130 bits for the piece which is the first 250 bits of an input
                    let prime_name = format!("prime_{}", name);
                    let (prime, z_prime) = self
                        .canon_bitshift_130(
                            layouter.namespace(|| prime_name),
                            whole.inner().cell_value(),
                            _debug_info,
                        )
                        .unwrap();

                    let name1 = format!("prime_{}", name.clone());
                    assert_synthesize_error!(
                        prime_cells.contains_key(&name1),
                        &format!("[{}] not in prime_cells", name1)
                    );
                    primes.insert(name1.clone(), Some(prime));

                    let name2 = format!("z13_{}", name1.clone());
                    assert_synthesize_error!(
                        prime_cells.contains_key(&name2),
                        &format!("[Sinsemilla] [{}] not in prime_cells", name2)
                    );
                    primes.insert(name2, Some(z_prime));
                }
            }

            pieces.insert(name.clone(), Some(whole.clone().inner().cell_value()));

            // get the order number of a z13 item
            let v = z13s.get_mut(&format!("z13_{}", name));
            if v.is_some() {
                let (i, _) = v.unwrap();
                *i = index;
            }

            message_pieces.push(whole)
        }

        // Check decomposition of y-coordinate of input
        for (name, (_, y, _)) in inputs {
            if !is_short_commit && y.is_some() && ylsbs.contains_key(name) {
                let (v_name, index) = &ylsbs[name];
                let y_lsb = piece_slices[v_name].1[*index].3.clone();

                desc = format!("[Sinsemilla] y[{}] decomposition", name);
                let y_lsb = self.y_canonicity(
                    layouter.namespace(|| desc),
                    y.clone().unwrap(),
                    y_lsb
                        .map(|y_lsb| y_lsb.value().map(|y_lsb| *y_lsb))
                        .unwrap_or(None),
                    _debug_info,
                )?;

                let v = piece_slices.get_mut(v_name).unwrap();
                let v = v.1.get_mut(*index).unwrap();
                *v = (v.0, v.1, None, Some(y_lsb));
            }
        }

        let message = Message::from_pieces(chip.clone(), message_pieces);
        let domain = CommitDomain::new(chip.clone(), ecc_chip, &self.commit_domain);
        let point = if is_short_commit {
            let (short_cm, zs) = domain.short_commit(
                layouter.namespace(|| "[Sinsemilla] Short Commit Hash"),
                message,
                r,
            )?;

            {
                ///////// handle zs /////////

                // update z13 value
                for (_name, (index, v)) in z13s.iter_mut() {
                    *v = Some(zs[*index][13].clone());
                }

                // update z1 value to corresponding slice
                for name in &z1_items {
                    let value = pieces.get_mut(name).unwrap();
                    if value.is_none() {
                        let name = Self::extract_piece_name(name);
                        let (index, _width) = z1_info[&name];
                        *value = Some(zs[index][1].clone());
                    }
                }
            }

            PointResult::X(Some(short_cm))
        } else {
            let (cm, zs) = domain.commit(
                layouter.namespace(|| "[Sinsemilla] Commit Hash"),
                message,
                r,
            )?;

            {
                ///////// handle zs /////////

                // update z13 value
                for (_name, (index, v)) in z13s.iter_mut() {
                    *v = Some(zs[*index][13].clone());
                }

                // update z1 value to corresponding slice
                for name in &z1_items {
                    let value = pieces.get_mut(name).unwrap();
                    if value.is_none() {
                        let name = Self::extract_piece_name(name);
                        let (index, _width) = z1_info[&name];
                        *value = Some(zs[index][1].clone());
                    }
                }
            }

            PointResult::Point(Some(cm))
        };

        // canonicity checks (need whole pieces)
        for gate in &input_gates {
            if gate.cells.len() > 2
                && gate.cells[0].width >= FILED_SIZE // >= 2^254 + 2^126
                && gate.cells[1].width < MAX_CANON_OFFSET
            {
                let prime_data = gate.cells[1..3]
                    .iter()
                    .filter_map(|cell| {
                        if CellType::is_piece_or_slice_cell(cell.celltype) {
                            let value = pieces.get(&cell.name).unwrap();
                            Some((cell.name.clone(), value.clone(), cell.width))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                if prime_data.len() > 1 {
                    let n: usize = if Self::check_if_same_pieces(&vec![
                        gate.cells[1].name.clone(),
                        gate.cells[2].name.clone(),
                    ]) {
                        130
                    } else {
                        140
                    };

                    let desc = format!("[Sinsemilla] [{}] canonicity", gate.cells[0].name);
                    let (prime, z_prime) = self.canon_bitshift_n(
                        layouter.namespace(|| desc.clone()),
                        n,
                        prime_data[0].1.clone().unwrap(),
                        prime_data[0].2,
                        prime_data[1].1.clone().unwrap(),
                        _debug_info,
                    )?;

                    let name1 = format!(
                        "prime_{}_{}",
                        prime_data[0].0.replace(SLICE_SEP, ""),
                        prime_data[1].0.replace(SLICE_SEP, "")
                    );
                    assert_synthesize_error!(
                        prime_cells.contains_key(&name1),
                        &format!("[Sinsemilla] [{}] not in prime_cells", name1)
                    );
                    primes.insert(name1.clone(), Some(prime));

                    let name2 = format!("z{}_{}", n / K, name1.clone());
                    assert_synthesize_error!(
                        prime_cells.contains_key(&name2),
                        &format!("[Sinsemilla] [{}] not in prime_cells", name2)
                    );
                    primes.insert(name2, Some(z_prime));
                }
            }
        }

        self.assign_gate(
            layouter.namespace(|| "[Sinsemilla] Assign gate cells"),
            inputs,
            &pieces,
            &primes,
            &z13s,
            _debug_info,
        )?;

        Ok(point)
    }

    fn assign_gate(
        &self,
        mut layouter: impl Layouter<pallas::Base>,
        inputs: &InputConfigMap,
        pieces: &BTreeMap<String, Option<AssignedCell<pallas::Base, pallas::Base>>>,
        primes: &BTreeMap<String, Option<AssignedCell<pallas::Base, pallas::Base>>>,
        z13s: &BTreeMap<String, (usize, Option<AssignedCell<pallas::Base, pallas::Base>>)>,
        _debug_info: &mut Option<BTreeMap<String, Vec<String>>>,
    ) -> Result<(), Error> {
        let mut assigned_values = HashMap::new();
        let mut none_debug_info = None;
        let mut desc: String;

        for i in 0..self.gates.len() {
            let gate = &self.gates[i];
            let mut count: usize = 0;

            desc = format!("[Sinsemilla] Commit MessagePiece [{}]", gate.cells[0].name);
            layouter.assign_region(
                || base::string_to_static_str(&desc),
                |mut region| {
                    self.qs[i].enable(&mut region, 0)?;
                    count += 1;

                    for cell in &gate.cells {
                        if cell.celltype == CellType::YSlice
                            && CellType::is_input_cell(gate.cells[0].celltype)
                        {
                            continue;
                        }
                        if cell.celltype == CellType::PadSlice {
                            continue;
                        }

                        let row = match cell.row {
                            RowType::Cur => 0,
                            RowType::Next => 1,
                            _ => panic!("[Sinsemilla] wrong row configured: [{:?}]", cell.row),
                        };

                        let cell_value = if CellType::is_piece_or_slice_cell(cell.celltype) {
                            pieces[&cell.name].clone()
                        } else if CellType::is_input_cell(cell.celltype) {
                            inputs[&cell.name].0.clone() // x-coordinate
                        } else if CellType::is_canonicity_or_prime_cell(cell.celltype) {
                            primes[&cell.name].clone()
                        } else if CellType::is_z13_cell(cell.celltype) {
                            z13s[&cell.name].1.clone()
                        } else {
                            panic!(
                                "[Sinsemilla] [{}]: wrong cell type: [{:?}]",
                                cell.name, cell.celltype
                            );
                        };

                        let cell_value = cell_value.unwrap();

                        if cell.celltype == CellType::TopSlice {
                            assert_synthesize_error!(
                                cell.width == 1,
                                &format!(
                                    "[Sinsemilla] [{}]: wrong top cell width: [{}]",
                                    cell.name, cell.width
                                )
                            );

                            let value = halo2api::assign_advice(
                                &mut region,
                                || base::string_to_static_str(&cell.name),
                                &self.advices,
                                cell.col,
                                row,
                                || Ok(*cell_value.value().unwrap()),
                                (
                                    if count == 1 {
                                        _debug_info
                                    } else {
                                        &mut none_debug_info
                                    },
                                    &cell.name,
                                ),
                            )?;
                            assigned_values.insert(cell.name.clone(), Some(value));
                        } else if CellType::is_input_cell(gate.cells[0].celltype)
                            && assigned_values.contains_key(&cell.name)
                        {
                            halo2api::copy_advice(
                                &assigned_values[&cell.name].as_ref().unwrap(),
                                &mut region,
                                || base::string_to_static_str(&cell.name),
                                &self.advices,
                                cell.col,
                                row,
                                (
                                    if count == 1 {
                                        _debug_info
                                    } else {
                                        &mut none_debug_info
                                    },
                                    &cell.name,
                                ),
                            )?;
                        } else {
                            halo2api::copy_advice(
                                &cell_value,
                                &mut region,
                                || base::string_to_static_str(&cell.name),
                                &self.advices,
                                cell.col,
                                row,
                                (
                                    if count == 1 {
                                        _debug_info
                                    } else {
                                        &mut none_debug_info
                                    },
                                    &cell.name,
                                ),
                            )?;
                        }
                    }

                    Ok(())
                },
            )?;
        }

        Ok(())
    }
}
