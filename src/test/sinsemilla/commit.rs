#![allow(dead_code)]

use halo2_proofs::arithmetic::{Field, FieldExt};
use pasta_curves::pallas;
use rand::{rngs::OsRng, RngCore};

use super::constants;
use crate::consts::*;
use crate::domains::*;
use crate::global;
use crate::sinsemilla::circuit::*;
use crate::types::*;

const COMMIT_DOMAIN_NAME: &str = "Sinsemilla Circuit Test";

fn add_circuit<T: ISinsemillaCircuit>(
    is_short_commit: bool,
    circuits: &mut Vec<SinsemillaCircuit<T>>,
    inputs: &Vec<(String, Option<pallas::Base>, Option<pallas::Base>)>,
) {
    global_domain::add_commit_domain(COMMIT_DOMAIN_NAME, constants::NUM_WINDOWS);
    circuits.push(SinsemillaCircuit::<T>::new(
        is_short_commit,
        COMMIT_DOMAIN_NAME,
        &inputs,
        Some(pallas::Scalar::random(OsRng)),
        &Vec::default(),
    ));
}

#[test]
pub fn short_commit() {
    global::config_generator_q(COMMIT_DOMAIN_NAME, &Some(constants::GENERATOR_Q));
    global::config_generator_r(COMMIT_DOMAIN_NAME, &Some(constants::GENERATOR_R));
    global::config_zs_and_us(
        COMMIT_DOMAIN_NAME,
        &Some((constants::Z.to_vec(), constants::U.to_vec())),
    );
    global::config_zs_and_us_short(
        COMMIT_DOMAIN_NAME,
        &Some((constants::Z_SHORT.to_vec(), constants::U_SHORT.to_vec())),
    );

    struct MyCircuitConfig {}

    impl ISinsemillaCircuit for MyCircuitConfig {
        fn get_commit_gate_config(_domain: &String) -> Vec<GateInfo> {
            /*
            refer https://zcash.github.io/orchard/design/circuit/gadgets/sinsemilla/commit-ivk.html

            gate b:
            | A_0 | A_1 | q |
            -----------------
            |  b  | b_0 | 1 |
            | b_1 | b_2 | 0 |

            gate d:
            | A_0 | A_1 | q |
            -----------------
            |  d  | d_0 | 1 |
            |     | d_1 | 0 |

            gate input1:
            |    A_0    |  A_1  |    A_2  |     A_3     |  q  |
            ---------------------------------------------------
            |   input1  |   a   |   b_0   |     b_1     |  1  |
            |           | z13_a | prime_a | z13_prime_a |  0  |

            gate input2:
            |    A_0   |  A_1  |     A_2    |       A_3      |  q  |
            --------------------------------------------------------
            |  input2  |  b_2  |      c     |       d_0      |  1  |
            |    d_1   | z13_c | prime_b2_c | z14_prime_b2_c |  0  |
            */
            vec![
                GateInfo {
                    name: "gate b".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "b".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Cur,
                            width: 10,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_1".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Next,
                            width: 5,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate d".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "d".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Cur,
                            width: 10,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Cur,
                            width: 9,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_1".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input1".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input1".to_string(),
                            celltype: CellType::Input,
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "a".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Cur,
                            width: 250,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_0".to_string(),
                            celltype: CellType::CanonicityCheckSlice,
                            coltype: ColType::Advice,
                            col: 2,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_1".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 3,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_a".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_a".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 2,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_prime_a".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 3,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input2".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input2".to_string(),
                            celltype: CellType::Input,
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Cur,
                            width: 5,
                            attr: None,
                        },
                        CellInfo {
                            name: "c".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 2,
                            row: RowType::Cur,
                            width: 240,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_0".to_string(),
                            celltype: CellType::CanonicityCheckSlice,
                            coltype: ColType::Advice,
                            col: 3,
                            row: RowType::Cur,
                            width: 9,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_1".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 0,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_c".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 1,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_b2_c".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 2,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z14_prime_b2_c".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 3,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
            ]
        }
    }

    let mut circuits: Vec<SinsemillaCircuit<MyCircuitConfig>> = Vec::new();

    add_circuit::<MyCircuitConfig>(
        true,
        &mut circuits,
        &vec![
            ("input1".to_string(), Some(pallas::Base::zero()), None),
            ("input2".to_string(), Some(pallas::Base::zero()), None),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            ("input1".to_string(), Some(pallas::Base::one()), None),
            ("input2".to_string(), Some(pallas::Base::one()), None),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(pallas::Base::from_u128(T_Q)),
                None,
            ),
            (
                "input2".to_string(),
                Some(pallas::Base::from_u128(T_Q)),
                None,
            ),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(pallas::Base::from_u128(T_Q - 1)),
                None,
            ),
            (
                "input2".to_string(),
                Some(pallas::Base::from_u128(T_Q - 1)),
                None,
            ),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(pallas::Base::from_u128(1 << 127)),
                None,
            ),
            (
                "input2".to_string(),
                Some(pallas::Base::from_u128(1 << 127)),
                None,
            ),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(pallas::Base::from_u128((1 << 127) - 1)),
                None,
            ),
            (
                "input2".to_string(),
                Some(pallas::Base::from_u128((1 << 127) - 1)),
                None,
            ),
        ],
    );
    let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
    add_circuit(
        true,
        &mut circuits,
        &vec![
            ("input1".to_string(), Some(two_pow_254), None),
            ("input2".to_string(), Some(two_pow_254), None),
        ],
    );
    add_circuit(
        true,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(two_pow_254 - pallas::Base::one()),
                None,
            ),
            (
                "input2".to_string(),
                Some(two_pow_254 - pallas::Base::one()),
                None,
            ),
        ],
    );

    for i in 0..circuits.len() {
        assert_eq!(circuits[i].mock_verify(11), Ok(()));
        println!(
            "[test]==> short_commit[{}]({}) verify ok!",
            i, COMMIT_DOMAIN_NAME
        );
    }
}

//#[test]
pub fn commit() {
    global::config_generator_q(COMMIT_DOMAIN_NAME, &Some(constants::GENERATOR_Q));
    global::config_generator_r(COMMIT_DOMAIN_NAME, &Some(constants::GENERATOR_R));
    global::config_zs_and_us(
        COMMIT_DOMAIN_NAME,
        &Some((constants::Z.to_vec(), constants::U.to_vec())),
    );
    global::config_zs_and_us_short(
        COMMIT_DOMAIN_NAME,
        &Some((constants::Z_SHORT.to_vec(), constants::U_SHORT.to_vec())),
    );

    struct MyCircuitConfig {}

    impl ISinsemillaCircuit for MyCircuitConfig {
        fn get_commit_gate_config(_domain: &String) -> Vec<GateInfo> {
            // refer https://zcash.github.io/orchard/design/circuit/gadgets/sinsemilla/note-commit.html

            // | A_6 | A_7 | A_8 | q |
            // -----------------------
            // |  b  | b_0 | b_1 | 1 |
            // |     | b_2 | b_3 | 0 |

            // | A_6 | A_7 | A_8 | q |
            // -----------------------
            // |  d  | d_0 | d_1 | 1 |
            // |     | d_2 | d_3 | 0 |

            // | A_6 | A_7 | A_8 | q |
            // -----------------------
            // |  e  | e_0 | e_1 | 1 |

            // | A_6 | A_7 | q |
            // -----------------
            // |  g  | g_0 | 1 |
            // | g_1 | g_2 | 0 |

            // | A_6 | A_7 | A_8 | q |
            // -----------------------
            // |  h  | h_0 | h_1 | 1 |

            // |    A_6    | A_7 |   A_8   |     A_9     | q |
            // -----------------------------------------------
            // | x(input1) | b_0 | a       | z13_a       | 1 |
            // |           | b_1 | prime_a | z13_prime_a | 0 |

            // |    A_6    | A_7 |    A_8     |      A_9       | q |
            // -----------------------------------------------------
            // | x(input2) | b_3 |    c       | z13_c          | 1 |
            // |           | d_0 | prime_b3_c | z14_prime_b3_c | 0 |

            // |  A_6  | A_7 | A_8 | A_9 | q |
            // -------------------------------
            // | value | d_2 | d_3 | e_0 | 1 |

            // |  A_6   | A_7 |    A_8     |      A_9       | q |
            // --------------------------------------------------
            // | input3 | e_1 |    f       | z13_f          | 1 |
            // |        | g_0 | prime_e1_f | z14_prime_e1_f | 0 |

            // |  A_6   | A_7 |     A_8     |       A_9       | q |
            // ----------------------------------------------------
            // | input4 | g_1 |   g_2       | z13_g           | 1 |
            // |  h_0   | h_1 | prime_g1_g2 | z13_prime_g1_g2 | 0 |

            /*
            Check decomposition and canonicity of y-coordinates.
            This is used for both y(input1) and y(input2).

            y = LSB || k_0 || k_1 || k_2 || k_3
              = (bit 0) || (bits 1..=9) || (bits 10..=249) || (bits 250..=253) || (bit 254)

            These pieces are laid out in the following configuration:
                    | A_5 | A_6 |  A_7  |   A_8   |     A_9     |
                    ---------------------------------------------
                    |  y  | lsb |  k_0  |   k_2   |     k_3     |
                    |  j  | z1_j| z13_j | j_prime | z13_j_prime |
            where z1_j = k_1.
            */
            vec![
                GateInfo {
                    name: "gate b".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "b".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 10,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_1".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_3".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: 4,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate d".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "d".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 60,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_0".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_1".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 8,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_3".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: 50,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate e".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "e".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 10,
                            attr: None,
                        },
                        CellInfo {
                            name: "e_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 6,
                            attr: None,
                        },
                        CellInfo {
                            name: "e_1".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate g".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "g".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 250,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_0".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_1".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Next,
                            width: 9,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 240,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate h".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "h".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 10,
                            attr: None,
                        },
                        CellInfo {
                            name: "h_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 5,
                            attr: None,
                        },
                        CellInfo {
                            name: "h_1".to_string(),
                            celltype: CellType::TopSlice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "h_2".to_string(),
                            celltype: CellType::PadSlice,
                            coltype: ColType::Advice,
                            col: 0,            //ignored
                            row: RowType::Cur, //ignored
                            width: 4,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input1".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input1".to_string(),
                            celltype: CellType::YInput,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "a".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 250,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_1".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_2".to_string(),
                            celltype: CellType::YSlice,
                            coltype: ColType::Advice,
                            col: 0,            //igored
                            row: RowType::Cur, //igored
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_a".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_a".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_prime_a".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input2".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input2".to_string(),
                            celltype: CellType::YInput,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "b_3".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "c".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 250,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_0".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_1".to_string(),
                            celltype: CellType::YSlice,
                            coltype: ColType::Advice,
                            col: 0,            //igored
                            row: RowType::Cur, //igored
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_c".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_b3_c".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z14_prime_b3_c".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate value".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "value".to_string(),
                            celltype: CellType::Input,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: 64,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 8,
                            attr: None,
                        },
                        CellInfo {
                            name: "d_3".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 50,
                            attr: None,
                        },
                        CellInfo {
                            name: "e_0".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Cur,
                            width: 6,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input3".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input3".to_string(),
                            celltype: CellType::Input,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "e_1".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 4,
                            attr: None,
                        },
                        CellInfo {
                            name: "f".to_string(),
                            celltype: CellType::Piece,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 250,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_0".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_f".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_e1_f".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z14_prime_e1_f".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
                GateInfo {
                    name: "gate input4".to_string(),
                    cells: vec![
                        CellInfo {
                            name: "input4".to_string(),
                            celltype: CellType::Input,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_1".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Cur,
                            width: 9,
                            attr: None,
                        },
                        CellInfo {
                            name: "g_2".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Cur,
                            width: 240,
                            attr: None,
                        },
                        CellInfo {
                            name: "h_0".to_string(),
                            celltype: CellType::Slice,
                            coltype: ColType::Advice,
                            col: 6,
                            row: RowType::Next,
                            width: 5,
                            attr: None,
                        },
                        CellInfo {
                            name: "h_1".to_string(),
                            celltype: CellType::Slice, //no TopSlice here
                            coltype: ColType::Advice,
                            col: 7,
                            row: RowType::Next,
                            width: 1,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_g".to_string(),
                            celltype: CellType::CanonicityCheckZ13,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Cur,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "prime_g1_g2".to_string(),
                            celltype: CellType::PrimeCheck,
                            coltype: ColType::Advice,
                            col: 8,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                        CellInfo {
                            name: "z13_prime_g1_g2".to_string(),
                            celltype: CellType::CanonicityCheck,
                            coltype: ColType::Advice,
                            col: 9,
                            row: RowType::Next,
                            width: FILED_SIZE,
                            attr: None,
                        },
                    ],
                },
            ]
        }
    }

    let mut rng = OsRng;
    let mut circuits: Vec<SinsemillaCircuit<MyCircuitConfig>> = Vec::new();

    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            ("input3".to_string(), Some(pallas::Base::zero()), None),
            ("input4".to_string(), Some(pallas::Base::zero()), None),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(pallas::Base::from_u128(T_Q - 1)),
                None,
            ),
            (
                "input4".to_string(),
                Some(pallas::Base::from_u128(T_Q - 1)),
                None,
            ),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(pallas::Base::from_u128(T_Q)),
                None,
            ),
            (
                "input4".to_string(),
                Some(pallas::Base::from_u128(T_Q)),
                None,
            ),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(pallas::Base::from_u128((1 << 127) - 1)),
                None,
            ),
            (
                "input4".to_string(),
                Some(pallas::Base::from_u128((1 << 127) - 1)),
                None,
            ),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(pallas::Base::from_u128(1 << 127)),
                None,
            ),
            (
                "input4".to_string(),
                Some(pallas::Base::from_u128(1 << 127)),
                None,
            ),
        ],
    );
    let two_pow_254 = pallas::Base::from_u128(1 << 127).square();
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(two_pow_254 - pallas::Base::one()),
                None,
            ),
            (
                "input4".to_string(),
                Some(two_pow_254 - pallas::Base::one()),
                None,
            ),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            ("input3".to_string(), Some(two_pow_254), None),
            ("input4".to_string(), Some(two_pow_254), None),
        ],
    );
    add_circuit::<MyCircuitConfig>(
        false,
        &mut circuits,
        &vec![
            (
                "input1".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "input2".to_string(),
                Some(-pallas::Base::one()),
                Some(pallas::Base::one()),
            ),
            (
                "value".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input3".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
            (
                "input4".to_string(),
                Some(pallas::Base::from(rng.next_u64())),
                None,
            ),
        ],
    );

    for i in 0..circuits.len() {
        assert_eq!(circuits[i].mock_verify(11), Ok(()));
        println!("[test]==> commit[{}]({}) verify ok!", i, COMMIT_DOMAIN_NAME);
    }
}
