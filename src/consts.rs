#![allow(dead_code)]

pub(crate) const T_Q: u128 = 45560315531506369815346746415080538113;
pub(crate) const T_P: u128 = 45560315531419706090280762371685220353;

pub const FILED_SIZE: usize = 255;

pub const L_MERKLE: usize = 255;
pub const MERKLE_DEPTH: usize = 32;

pub const DOMAIN_MERKLECRH: &'static str = "domain_merklecrh";

// input attributes
pub const ATTRIBUTE_VALUE: &'static str = "Value";
pub const ATTRIBUTE_MERKLEPATH: &'static str = "MerklePath:";
pub const ATTRIBUTE_FIELD: &'static str = "Field";
pub const ATTRIBUTE_POINT: &'static str = "Point";
pub const ATTRIBUTE_NIPOINT: &'static str = "NIPoint";
pub const ATTRIBUTE_SCALAR: &'static str = "Scalar";
// intermedium attributes
pub const ATTRIBUTE_CELL: &'static str = "Cell";
pub const ATTRIBUTE_COMMIT_CELL: &'static str = "CommitCell";

// signs
pub const SIGN_OF_OLD_VALUE: &'static str = "old_";
pub const SIGN_OF_NEW_VALUE: &'static str = "new_";
pub const SIGN_OF_MAGNITUDE: &'static str = "magnitude_";
pub const SIGN_OF_SIGN: &'static str = "sign_";
pub const SIGN_OF_ANCHOR: &'static str = "anchor_";
pub const SIGN_OF_X: &'static str = "_x";
pub const SIGN_OF_Y: &'static str = "_y";

pub const SIGN_OF_CONSTRAINT: &'static str = "constraint";
pub const SIGN_OF_CONSTRAINT_COMMIT: &'static str = "constraint-commit";
