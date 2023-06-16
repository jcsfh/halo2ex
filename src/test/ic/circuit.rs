use ff::Field;
use funty::Signed;
use group::{Curve, GroupEncoding};
use halo2_proofs::{
    arithmetic::{CurveAffine, CurveExt},
    dev::MockProver,
};
use pasta_curves::pallas;
use rand::{rngs::OsRng, RngCore};

use super::constants;
use crate::circuit::base::*;
use crate::circuit::ic::*;
use crate::circuit::proof::*;
use crate::consts::*;
use crate::domains::*;
use crate::global;
use crate::primitives::{
    commitment::*, keys::*, nippoint::*, nullifier::*, tree::*, utils::*, value::*,
};
use crate::types::*;

pub const NUM_WINDOWS: usize = halo2_gadgets::ecc::chip::constants::NUM_WINDOWS; //85
pub const NUM_WINDOWS_SHORT: usize = halo2_gadgets::ecc::chip::constants::NUM_WINDOWS_SHORT; //22

const K: u32 = 11;
const MERKLE_DOMAIN_NAME: &'static str = "HashDomains_MerkleCRH_ICTest";
const NETCV_DOMAIN_NAME: &'static str = "HashDomains_NetCV_ICTest";

const FIXED_DOMAIN_NAME_1: &'static str = "fexed_domain_name_test_1";
const FIXED_DOMAIN_NAME_2: &'static str = "fexed_domain_name_test_2";

const NULLIFIER_K_DOMAIN_NAME: &'static str = "NullifierK_Test";
const AUTH_G_DOMAIN_NAME: &'static str = "AuthG_Test";
const VALUE_COMMIT_R_DOMAIN_NAME: &'static str = "ValueCommitR_Test";
const VALUE_COMMIT_V_DOMAIN_NAME: &'static str = "ValueCommitV_Test";

const SHORT_COMMIT_DOMAIN_NAME: &'static str = "short_commit_domain_name_test";
const COMMIT_DOMAIN_NAME: &'static str = "commit_domain_name_test";

type ValueNumType = i64;

#[derive(Copy, Clone, Debug, Default)]
struct ICTest {}

// refer https://github.com/zcash/orchard/blob/main/src/circuit.rs
impl ICConfig for ICTest {
    type Value = ValueNumType;

    fn get_ic_configs() -> (Vec<GateConfig>, Vec<Vec<AlgoConfig>>) {
        let gate_configs = vec![
            (
                "old_v - new_v = magnitude * sign".to_string(),
                vec![
                    (
                        format!("{}v", SIGN_OF_OLD_VALUE), //old_v
                        ATTRIBUTE_VALUE.to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        0,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        format!("{}v", SIGN_OF_NEW_VALUE), //new_v
                        ATTRIBUTE_VALUE.to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        1,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        format!("{}v", SIGN_OF_MAGNITUDE), //magnitude_v
                        "".to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        2,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        format!("{}v", SIGN_OF_SIGN), //sign_v
                        "".to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        3,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        format!("{}merklecrh_cm", SIGN_OF_ANCHOR), //anchor_merklecrh_cm
                        format!(
                            "{}merklecrh_cm#{}#cm_old",
                            ATTRIBUTE_MERKLEPATH, MERKLE_DOMAIN_NAME
                        ),
                        "Input".to_string(),
                        "Advice".to_string(),
                        4,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        "pub_input_anchor".to_string(),
                        "".to_string(),
                        "Instance".to_string(),
                        "Advice".to_string(),
                        5,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        "enable_spends".to_string(),
                        "".to_string(),
                        "Instance".to_string(),
                        "Advice".to_string(),
                        6,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        "enable_outputs".to_string(),
                        "".to_string(),
                        "Instance".to_string(),
                        "Advice".to_string(),
                        7,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                ],
            ),
            (
                "poseidon_hash(nk, rho_old) + psi_old".to_string(),
                vec![
                    (
                        "sum".to_string(),
                        "".to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        6,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        "hash_old".to_string(),
                        "".to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        7,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                    (
                        "psi_old".to_string(),
                        "".to_string(),
                        "Input".to_string(),
                        "Advice".to_string(),
                        8,
                        "Cur".to_string(),
                        FILED_SIZE,
                    ),
                ],
            ),
        ];

        let algo_configs = vec![
            vec![
                (
                    "".to_string(),
                    "old_v - new_v - (magnitude_v * sign_v)".to_string(),
                    vec![
                        (
                            "".to_string(),
                            "v".to_string(),
                            "old_v - new_v".to_string(),
                            ("old_v".to_string(), "".to_string()),
                            "sub".to_string(),
                            Some(("new_v".to_string(), "".to_string())),
                        ),
                        //the above result "sub" the below because the operator next (the first item below) is sub!
                        (
                            "sub".to_string(),
                            "".to_string(),
                            "magnitude_v * sign_v".to_string(),
                            ("magnitude_v".to_string(), "".to_string()),
                            "mul".to_string(),
                            Some(("sign_v".to_string(), "".to_string())),
                        ),
                    ],
                ),
                (
                    "".to_string(),
                    "Either old_v = 0, or anchor equals public input".to_string(),
                    vec![
                        (
                            "".to_string(),
                            "".to_string(),
                            "old_v".to_string(),
                            ("old_v".to_string(), "".to_string()),
                            "".to_string(),
                            None,
                        ),
                        // above "mul" below
                        (
                            "mul".to_string(),
                            "".to_string(),
                            "anchor - pub_input_anchor".to_string(),
                            ("anchor_merklecrh_cm".to_string(), "".to_string()),
                            "sub".to_string(),
                            Some(("pub_input_anchor".to_string(), "".to_string())),
                        ),
                    ],
                ),
                (
                    "".to_string(),
                    "old_v = 0 or enable_spends = 1".to_string(),
                    vec![
                        (
                            "".to_string(),
                            "".to_string(),
                            "old_v".to_string(),
                            ("old_v".to_string(), "".to_string()),
                            "".to_string(),
                            None,
                        ),
                        (
                            "mul".to_string(),
                            "".to_string(),
                            "1 - enable_spends".to_string(),
                            ("enable_spends".to_string(), "".to_string()),
                            "boolean_neg".to_string(),
                            None,
                        ),
                    ],
                ),
                (
                    "".to_string(),
                    "old_v = 0 or enable_spends = 1".to_string(),
                    vec![
                        (
                            "".to_string(),
                            "".to_string(),
                            "old_v".to_string(),
                            ("old_v".to_string(), "".to_string()),
                            "".to_string(),
                            None,
                        ),
                        (
                            "mul".to_string(),
                            "".to_string(),
                            "1 - enable_spends".to_string(),
                            ("enable_spends".to_string(), "".to_string()),
                            "boolean_neg".to_string(),
                            None,
                        ),
                    ],
                ),
            ],
            // the followings for constraints
            vec![(
                "".to_string(),
                "poseidon_hash(nk, rho_old) + psi_old".to_string(),
                vec![
                    (
                        "".to_string(),
                        "".to_string(),
                        "hash_old + psi_old".to_string(),
                        ("hash_old".to_string(), "".to_string()),
                        "add".to_string(),
                        Some(("psi_old".to_string(), "".to_string())),
                    ),
                    (
                        "sub".to_string(),
                        "".to_string(),
                        "sum".to_string(),
                        ("sum".to_string(), "".to_string()),
                        "".to_string(),
                        None,
                    ),
                ],
            )],
            vec![(
                "constraint".to_string(),
                "net_cv =  [v] ValueCommitV + [rcv] ValueCommitR".to_string(),
                vec![
                    (
                        "".to_string(),
                        "commitment".to_string(),
                        "[v] ValueCommitV".to_string(),
                        ("v".to_string(), "MagnitudeSign".to_string()),
                        "mul".to_string(),
                        Some(("ValueCommitV".to_string(), "ShortField".to_string())),
                    ),
                    (
                        "add".to_string(),
                        "net_cv".to_string(),
                        "[rcv] ValueCommitR".to_string(),
                        ("rcv".to_string(), "Scalar".to_string()),
                        "mul".to_string(),
                        Some(("ValueCommitR".to_string(), "FullField".to_string())),
                    ),
                ],
            )],
            vec![(
                "constraint".to_string(),
                "nf_old = cm_old + [poseidon_hash(nk, rho_old) + psi_old]NullifierK".to_string(),
                vec![
                    (
                        "".to_string(),
                        "hash_old".to_string(),
                        "poseidon_hash(nk, rho_old)".to_string(),
                        ("nk".to_string(), "Cell".to_string()),
                        "poseidon".to_string(),
                        Some(("rho_old".to_string(), "Cell".to_string())),
                    ),
                    (
                        "add".to_string(),
                        "sum".to_string(),
                        "hash_old + psi_old".to_string(),
                        ("psi_old".to_string(), "Field".to_string()),
                        "".to_string(),
                        None,
                    ),
                    (
                        "mul".to_string(),
                        "product".to_string(),
                        "[sum]NullifierK".to_string(),
                        ("NullifierK".to_string(), "BaseField".to_string()),
                        "".to_string(),
                        None,
                    ),
                    (
                        "add".to_string(),
                        "nf_old".to_string(),
                        "product + cm_old".to_string(),
                        ("cm_old".to_string(), "Point".to_string()),
                        "".to_string(),
                        None,
                    ),
                ],
            )],
            vec![(
                "constraint".to_string(),
                "rk = [alpha] SpendAuthG + ak".to_string(),
                vec![
                    (
                        "".to_string(),
                        "alpha_commitment".to_string(),
                        "[alpha] AuthG".to_string(),
                        ("alpha".to_string(), "Scalar".to_string()),
                        "mul".to_string(),
                        Some(("AuthG".to_string(), "FullField".to_string())),
                    ),
                    (
                        "add".to_string(),
                        "rk".to_string(),
                        "alpha_commitment + ak".to_string(),
                        ("ak".to_string(), "NIPoint".to_string()),
                        "".to_string(),
                        None,
                    ),
                ],
            )],
            vec![(
                "constraint-commit".to_string(),
                "derived_pk_d_old = [ivk] g_d_old".to_string(),
                vec![(
                    "".to_string(),
                    "constraint_derived_pk_d_old".to_string(),
                    "[ivk] g_d_old".to_string(),
                    ("ivk".to_string(), "CommitCell".to_string()),
                    "mul".to_string(),
                    Some(("g_d_old".to_string(), "NIPoint".to_string())),
                )],
            )],
            vec![(
                "constraint-commit".to_string(),
                "check derived_cm".to_string(),
                vec![(
                    "".to_string(),
                    "derived_cm".to_string(),
                    "".to_string(),
                    ("derived_cm".to_string(), "CommitCell".to_string()),
                    "".to_string(),
                    None,
                )],
            )],
        ];

        (gate_configs, algo_configs)
    }

    fn get_commit_gate_configs(domain: &String) -> Option<Vec<GateConfig>> {
        if domain == SHORT_COMMIT_DOMAIN_NAME {
            Some(vec![
                (
                    "gate b".to_string(),
                    vec![
                        (
                            "b".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            10,
                        ),
                        (
                            "b_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            1,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "b_1".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            0,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "b_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            1,
                            "Next".to_string(),
                            5,
                        ),
                    ],
                ),
                (
                    "gate d".to_string(),
                    vec![
                        (
                            "d".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            10,
                        ),
                        (
                            "d_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            1,
                            "Cur".to_string(),
                            9,
                        ),
                        (
                            "d_1".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            1,
                            "Next".to_string(),
                            1,
                        ),
                    ],
                ),
                (
                    "gate ak".to_string(),
                    vec![
                        (
                            "ak".to_string(),
                            "".to_string(),
                            "Input".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "a".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            1,
                            "Cur".to_string(),
                            250,
                        ),
                        (
                            "b_0".to_string(),
                            "".to_string(),
                            "CanonicityCheckSlice".to_string(),
                            "Advice".to_string(),
                            2,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "b_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            3,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "z13_a".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            1,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_a".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            2,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z13_prime_a".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            3,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
                (
                    "gate nk".to_string(),
                    vec![
                        (
                            "nk".to_string(),
                            "".to_string(),
                            "Input".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "b_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            1,
                            "Cur".to_string(),
                            5,
                        ),
                        (
                            "c".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            2,
                            "Cur".to_string(),
                            240,
                        ),
                        (
                            "d_0".to_string(),
                            "".to_string(),
                            "CanonicityCheckSlice".to_string(),
                            "Advice".to_string(),
                            3,
                            "Cur".to_string(),
                            9,
                        ),
                        (
                            "d_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            0,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "z13_c".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            1,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_b2_c".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            2,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z14_prime_b2_c".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            3,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
            ])
        } else if domain == COMMIT_DOMAIN_NAME {
            Some(vec![
                (
                    "gate b".to_string(),
                    vec![
                        (
                            "b".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            10,
                        ),
                        (
                            "b_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "b_1".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "b_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "b_3".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            4,
                        ),
                    ],
                ),
                (
                    "gate d".to_string(),
                    vec![
                        (
                            "d".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            60,
                        ),
                        (
                            "d_0".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "d_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "d_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            8,
                        ),
                        (
                            "d_3".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            50,
                        ),
                    ],
                ),
                (
                    "gate e".to_string(),
                    vec![
                        (
                            "e".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            10,
                        ),
                        (
                            "e_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            6,
                        ),
                        (
                            "e_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            4,
                        ),
                    ],
                ),
                (
                    "gate g".to_string(),
                    vec![
                        (
                            "g".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            250,
                        ),
                        (
                            "g_0".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "g_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            6,
                            "Next".to_string(),
                            9,
                        ),
                        (
                            "g_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            240,
                        ),
                    ],
                ),
                (
                    "gate h".to_string(),
                    vec![
                        (
                            "h".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            10,
                        ),
                        (
                            "h_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            5,
                        ),
                        (
                            "h_1".to_string(),
                            "".to_string(),
                            "TopSlice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "h_2".to_string(),
                            "".to_string(),
                            "PadSlice".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            4,
                        ),
                    ],
                ),
                (
                    "gate g_d_old".to_string(),
                    vec![
                        (
                            "g_d_old".to_string(),
                            "".to_string(),
                            "YInput".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "a".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            250,
                        ),
                        (
                            "b_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "b_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "b_2".to_string(),
                            "".to_string(),
                            "YSlice".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "z13_a".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            9,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_a".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z13_prime_a".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            9,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
                (
                    "gate pk_d_new".to_string(),
                    vec![
                        (
                            "pk_d_new".to_string(),
                            "".to_string(),
                            "YInput".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "b_3".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "c".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            250,
                        ),
                        (
                            "d_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "d_1".to_string(),
                            "".to_string(),
                            "YSlice".to_string(),
                            "Advice".to_string(),
                            0,
                            "Cur".to_string(),
                            1,
                        ),
                        (
                            "z13_c".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            9,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_b3_c".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z14_prime_b3_c".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            9,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
                (
                    "gate new_v".to_string(),
                    vec![
                        (
                            "new_v".to_string(),
                            "".to_string(),
                            "Input".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            64,
                        ),
                        (
                            "d_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            8,
                        ),
                        (
                            "d_3".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            50,
                        ),
                        (
                            "e_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            9,
                            "Cur".to_string(),
                            6,
                        ),
                    ],
                ),
                (
                    "gate nf_old".to_string(),
                    vec![
                        (
                            "nf_old".to_string(),
                            "".to_string(),
                            "Input".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "e_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            4,
                        ),
                        (
                            "f".to_string(),
                            "".to_string(),
                            "Piece".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            250,
                        ),
                        (
                            "g_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "z13_f".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            9,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_e1_f".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z14_prime_e1_f".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            9,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
                (
                    "gate psi_old".to_string(),
                    vec![
                        (
                            "psi_old".to_string(),
                            "".to_string(),
                            "Input".to_string(),
                            "Advice".to_string(),
                            6,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "g_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Cur".to_string(),
                            9,
                        ),
                        (
                            "g_2".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            8,
                            "Cur".to_string(),
                            240,
                        ),
                        (
                            "h_0".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            6,
                            "Next".to_string(),
                            5,
                        ),
                        (
                            "h_1".to_string(),
                            "".to_string(),
                            "Slice".to_string(),
                            "Advice".to_string(),
                            7,
                            "Next".to_string(),
                            1,
                        ),
                        (
                            "z13_g".to_string(),
                            "".to_string(),
                            "CanonicityCheckZ13".to_string(),
                            "Advice".to_string(),
                            9,
                            "Cur".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "prime_g1_g2".to_string(),
                            "".to_string(),
                            "PrimeCheck".to_string(),
                            "Advice".to_string(),
                            8,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                        (
                            "z13_prime_g1_g2".to_string(),
                            "".to_string(),
                            "CanonicityCheck".to_string(),
                            "Advice".to_string(),
                            9,
                            "Next".to_string(),
                            FILED_SIZE,
                        ),
                    ],
                ),
            ])
        } else {
            None
        }
    }

    fn get_commit_configs(
    ) -> Option<Vec<(bool, String, (String, usize), Vec<(String, String)>, String)>> {
        Some(vec![
            (
                true,
                "ivk".to_string(),
                (SHORT_COMMIT_DOMAIN_NAME.to_string(), NUM_WINDOWS_SHORT),
                vec![
                    ("ak".to_string(), "".to_string()),
                    ("nk".to_string(), "".to_string()),
                ],
                "rivk".to_string(),
            ),
            (
                false,
                "derived_cm".to_string(),
                (COMMIT_DOMAIN_NAME.to_string(), NUM_WINDOWS),
                vec![
                    ("g_d_old".to_string(), "NIPoint".to_string()),
                    ("pk_d_new".to_string(), "NIPoint".to_string()), //must specify type here
                    ("new_v".to_string(), "".to_string()),
                    ("nf_old".to_string(), "".to_string()),
                    ("psi_old".to_string(), "".to_string()),
                ],
                "rcm".to_string(),
            ),
        ])
    }
}

impl InstanceOrder for ICTest {
    fn get_instance_order() -> Vec<String> {
        vec![
            "enable_spends".to_string(),
            "enable_outputs".to_string(),
            "pub_input_anchor".to_string(),
            "nf_old".to_string(),
            "net_cv_x".to_string(),
            "net_cv_y".to_string(),
            "rk_x".to_string(),
            "rk_y".to_string(),
            "derived_cm".to_string(),
        ]
    }
}

#[derive(Debug, Clone)]
pub struct ValidatingKeyRandomizer;
impl Randomizer for ValidatingKeyRandomizer {
    fn randomize(
        base: &pallas::Point,
        randomizer: &pallas::Scalar,
        domain_name: &str,
        h: &[u8; 1],
    ) -> pallas::Point {
        ValidatingKey::<ValidatingKeyRandomizer>::basepoint(domain_name, h) * randomizer + base
    }
}

impl Nullifier {
    pub fn derive(
        domain_name: &str,
        inputs: &[pallas::Base; 2],
        addend: pallas::Base,
        cm: Commitment,
    ) -> Self {
        let k = pallas::Point::hash_to_curve(domain_name)(b"K");

        Nullifier(extract_p(
            &(k * mod_r_p(poseidon_hash::<2>(inputs) + addend) + cm.0),
        ))
    }
}

impl ValueCommitment {
    #[allow(non_snake_case)]
    pub fn derive<S: Signed>(domain: &str, value: ValueType<S>, rcv: ValueCommitTrapdoor) -> Self {
        debug_assert!(ValueType::<S>::is_valid_range(value.value(), true));

        let hasher = pallas::Point::hash_to_curve(domain);
        let V = hasher(&*b"v");
        let R = hasher(&*b"r");
        let abs_value = S::try_from(value.value().abs()).expect("value must be in valid range");

        let abs_value = abs_value.as_i128(); // never fail
        let value = if value.value().is_negative() {
            -pallas::Scalar::from(abs_value as u64)
        } else {
            pallas::Scalar::from(abs_value as u64)
        };

        ValueCommitment::from(V * value + R * rcv.value())
    }
}

fn generate_circuit_instance<R: RngCore>(mut rng: R) -> (ICCircuit<ICTest>, Instance<ICTest>) {
    let mut circuit = ICCircuit::<ICTest>::default();
    let mut instance = Instance::<ICTest>::default();

    // test value and merklecrh
    let old_v = ValueType::<ValueNumType>::from(rand::random::<u32>() as ValueNumType).unwrap(); //OverflowError if overflowed
    let new_v = ValueType::<ValueNumType>::from(rand::random::<u32>() as ValueNumType).unwrap();
    circuit.add_values("v", &(old_v, new_v));

    let path = MerklePath::dummy(&mut rng);
    let cm_old = Commitment::dummy(&mut rng);
    circuit.add_point("cm_old", cm_old.as_ref());
    let anchor = path.root(cm_old.clone().into());

    circuit.add_merkle_data(
        "merklecrh_cm",
        &(MERKLE_DOMAIN_NAME, "cm_old", path.auth_path()),
        path.position(),
    );

    let nk = Nullifier::dummy(&mut rng);
    let rho_old = Nullifier::dummy(&mut rng);
    let psi_old = pallas::Base::random(&mut rng);
    let nf_old = Nullifier::derive(
        FIXED_DOMAIN_NAME_1,
        &[nk.value().clone(), rho_old.value()],
        psi_old,
        cm_old,
    );

    circuit.add_field("nk", &nk.value());
    circuit.add_field("rho_old", &rho_old.value());
    circuit.add_field("psi_old", &psi_old);

    let rcv = ValueCommitTrapdoor::random(&mut rng);
    circuit.add_scalar("rcv", &rcv.value());
    let net_cv =
        ValueCommitment::derive(FIXED_DOMAIN_NAME_2, (old_v - new_v).unwrap(), rcv.clone());

    let alpha = pallas::Scalar::random(&mut rng);
    let ak = ValidatingKey::<ValidatingKeyRandomizer>::dummy(&mut rng);
    let rk = ak.randomize(&alpha, FIXED_DOMAIN_NAME_1, b"G");
    let rk = pallas::Point::from_bytes(&rk.clone().into())
        .unwrap()
        .to_affine()
        .coordinates()
        .unwrap();
    circuit.add_scalar("alpha", &alpha);
    circuit.add_nipoint("ak", &(&ak).into());

    let g_d_old = NonIdentityPallasPoint::dummy(&mut rng);
    circuit.add_nipoint("g_d_old", &g_d_old.value());

    {
        // test short commit
        let rivk = pallas::Scalar::random(&mut rng);
        circuit.add_scalar("rivk", &rivk);

        let inputs = vec![
            (
                "ak".to_string(),
                FILED_SIZE, // same as configured in the gate above for "ak"
                Some(ak.point.to_affine().coordinates().unwrap().x().clone()),
                None,
            ),
            ("nk".to_string(), FILED_SIZE, Some(nk.value().clone()), None),
        ];

        let result = compute_commit_value(true, SHORT_COMMIT_DOMAIN_NAME, &rivk, &inputs);
        match result {
            CommitResult::X(x) => {
                let ivk = mod_r_p(x.clone().unwrap());
                circuit.add_constraint_point(
                    "constraint_derived_pk_d_old",
                    &g_d_old.mul(&ivk).value(),
                );
            }
            _ => {}
        }
    }

    // test commit
    let derived_cm: ExtractedCommitment = {
        let pk_d_new = NonIdentityPallasPoint::dummy(&mut rng);
        circuit.add_nipoint("pk_d_new", &(&pk_d_new).value());

        let g_d_old = g_d_old.to_affine().coordinates();
        let pk_d_new = pk_d_new.to_affine().coordinates();

        let inputs = vec![
            (
                "g_d_old".to_string(),
                FILED_SIZE, // same as configured in the gate above for "g_d_old"
                Some(*g_d_old.clone().unwrap().x()),
                Some(*g_d_old.clone().unwrap().y()),
            ),
            (
                "pk_d_new".to_string(),
                FILED_SIZE,
                Some(*pk_d_new.clone().unwrap().x()),
                Some(*pk_d_new.clone().unwrap().y()),
            ),
            ("new_v".to_string(), 64, new_v.to_base(), None),
            ("nf_old".to_string(), FILED_SIZE, Some(nf_old.value()), None),
            (
                "psi_old".to_string(),
                FILED_SIZE,
                Some(psi_old.clone()),
                None,
            ),
        ];

        let rcm = pallas::Scalar::random(&mut rng);
        circuit.add_scalar("rcm", &rcm);

        let result = compute_commit_value(false, COMMIT_DOMAIN_NAME, &rcm, &inputs);
        match result {
            CommitResult::Point(Some(p)) => Commitment(p).into(),
            _ => panic!("wrong type of commit result"),
        }
    };

    // fill instances
    instance.enables.insert("enable_spends".to_string(), true);
    instance.enables.insert("enable_outputs".to_string(), true);
    instance
        .fields
        .insert("pub_input_anchor".to_string(), anchor.value());
    instance.fields.insert("nf_old".to_string(), nf_old.value());
    instance.fields.insert("net_cv_x".to_string(), net_cv.x());
    instance.fields.insert("net_cv_y".to_string(), net_cv.y());
    instance.fields.insert("rk_x".to_string(), *rk.x());
    instance.fields.insert("rk_y".to_string(), *rk.y());
    instance
        .fields
        .insert("derived_cm".to_string(), derived_cm.value());

    (circuit, instance)
}

#[test]
pub fn test_ic() {
    let mut rng = OsRng;

    // configure domains
    {
        global::config_domain_name(DOMAIN_MERKLECRH, MERKLE_DOMAIN_NAME);
        global::config_generator_q(MERKLE_DOMAIN_NAME, &Some(constants::merklecrh::Q));
        global::config_generator_q(NETCV_DOMAIN_NAME, &Some(constants::netcv::Q));

        // NullifierK -> FIXED_DOMAIN_NAME_1 -> NULLIFIER_K_DOMAIN_NAME
        global::config_fixedpointbasefield("NullifierK", NULLIFIER_K_DOMAIN_NAME, NUM_WINDOWS);
        global::config_generator(
            NULLIFIER_K_DOMAIN_NAME,
            &Some(constants::nullifier_k::GENERATOR),
        );
        global::config_zs_and_us(
            NULLIFIER_K_DOMAIN_NAME,
            &Some((
                constants::nullifier_k::Z.to_vec(),
                constants::nullifier_k::U.to_vec(),
            )),
        );

        // AuthG -> FIXED_DOMAIN_NAME_1 -> AUTH_G_DOMAIN_NAME
        global::config_fixedbasefull("AuthG", AUTH_G_DOMAIN_NAME, NUM_WINDOWS);
        global::config_generator(AUTH_G_DOMAIN_NAME, &Some(constants::auth_g::GENERATOR));
        global::config_base_point(FIXED_DOMAIN_NAME_1, &constants::auth_g::GENERATOR.0);
        global::config_zs_and_us(
            AUTH_G_DOMAIN_NAME,
            &Some((constants::auth_g::Z.to_vec(), constants::auth_g::U.to_vec())),
        );

        // ValueCommitR -> FIXED_DOMAIN_NAME_2 -> VALUE_COMMIT_R_DOMAIN_NAME
        global::config_fixedbasefull("ValueCommitR", VALUE_COMMIT_R_DOMAIN_NAME, NUM_WINDOWS);
        global::config_generator(
            VALUE_COMMIT_R_DOMAIN_NAME,
            &Some(constants::valuecommit_r::GENERATOR),
        );
        global::config_zs_and_us(
            VALUE_COMMIT_R_DOMAIN_NAME,
            &Some((
                constants::valuecommit_r::Z.to_vec(),
                constants::valuecommit_r::U.to_vec(),
            )),
        );

        // ValueCommitV -> FIXED_DOMAIN_NAME_2 -> VALUE_COMMIT_V_DOMAIN_NAME
        global::config_fixedpointshort(
            "ValueCommitV",
            VALUE_COMMIT_V_DOMAIN_NAME,
            NUM_WINDOWS_SHORT,
        );
        global::config_generator(
            VALUE_COMMIT_V_DOMAIN_NAME,
            &Some(constants::valuecommit_v::GENERATOR),
        );
        global::config_zs_and_us_short(
            VALUE_COMMIT_V_DOMAIN_NAME,
            &Some((
                constants::valuecommit_v::Z.to_vec(),
                constants::valuecommit_v::U.to_vec(),
            )),
        );

        // sinsemilla short commit
        global::config_generator_q(
            SHORT_COMMIT_DOMAIN_NAME,
            &Some(constants::short_commit::GENERATOR_Q),
        );
        global::config_generator_r(
            SHORT_COMMIT_DOMAIN_NAME,
            &Some(constants::short_commit::GENERATOR_R),
        );
        global::config_zs_and_us(
            SHORT_COMMIT_DOMAIN_NAME,
            &Some((
                constants::short_commit::Z.to_vec(),
                constants::short_commit::U.to_vec(),
            )),
        );
        global::config_zs_and_us_short(
            SHORT_COMMIT_DOMAIN_NAME,
            &Some((
                constants::short_commit::Z_SHORT.to_vec(),
                constants::short_commit::U_SHORT.to_vec(),
            )),
        );

        // sinsemilla commit
        global::config_generator_q(COMMIT_DOMAIN_NAME, &Some(constants::commit::GENERATOR_Q));
        global::config_generator_r(COMMIT_DOMAIN_NAME, &Some(constants::commit::GENERATOR_R));
        global::config_zs_and_us(
            COMMIT_DOMAIN_NAME,
            &Some((constants::commit::Z.to_vec(), constants::commit::U.to_vec())),
        );
    }

    let (circuits, instances): (Vec<_>, Vec<_>) =
        (0..5).map(|_i| generate_circuit_instance(&mut rng)).unzip();

    for (circuit, instance) in circuits.iter().zip(instances.iter()) {
        assert_eq!(
            MockProver::run(K, circuit, instance.to_halo2_instance())
                .unwrap()
                .verify(),
            Ok(())
        );
    }
    println!("[test]==> MockProver passed");

    let vk = VerifyingKey::build::<ICTest>(K);
    println!("[test]==> build vk completed");
    let pk = ProvingKey::build::<ICTest>(K);
    println!("[test]==> build pk completed");

    let first_batch = 2;
    {
        let expected_proof_size =
            Proof::get_expected_proof_size(&circuits[..first_batch], &instances[..first_batch], K);
        println!("[test]==> expected_proof_size: {}", expected_proof_size);
        let proof = Proof::create(
            &pk,
            &circuits[..first_batch],
            &instances[..first_batch],
            &mut rng,
        )
        .unwrap();
        println!("[test]==> create proof completed");
        assert!(proof.verify(&vk, &instances[..first_batch]).is_ok());
        println!("[test]==> verify proof completed");
        assert_eq!(proof.as_ref().len(), expected_proof_size);
    }

    {
        let expected_proof_size =
            Proof::get_expected_proof_size(&circuits[first_batch..], &instances[first_batch..], K);
        println!("[test]==> expected_proof_size: {}", expected_proof_size);
        let proof = Proof::create(
            &pk,
            &circuits[first_batch..],
            &instances[first_batch..],
            &mut rng,
        )
        .unwrap();
        println!("[test]==> create proof completed");
        assert!(proof.verify(&vk, &instances[first_batch..]).is_ok());
        println!("[test]==> verify proof completed");
        assert_eq!(proof.as_ref().len(), expected_proof_size);
    }
}
