//#![allow(dead_code)]
//#![allow(unused_variables)]

use halo2_gadgets::ecc::chip::H;
use halo2_proofs::dev::VerifyFailure;
use pasta_curves::{arithmetic::CurveAffine, pallas};

pub type TGenerator = ([u8; 32], [u8; 32]);
pub type TVecZsUs<C> = Vec<(u64, [<C as CurveAffine>::Base; H])>;
pub type TZsUs = (Vec<u64>, Vec<[[u8; 32]; H]>);
pub type TZs = Vec<u64>;
pub type TUs = Vec<[[u8; 32]; H]>;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ColType {
    Constant,
    Selector,
    Fixed,
    Advice,
    Instance,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CellType {
    Input,
    YInput,
    Instance,
    Piece,
    Slice,
    TopSlice,
    PadSlice,
    YSlice,
    CanonicityCheckSlice,
    CanonicityCheckZ13,
    CanonicityCheck,
    PrimeCheck,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RowType {
    Cur,
    Next,
    Prev,
}

#[derive(Clone, Debug)]
pub struct CellInfo {
    pub name: String,
    pub celltype: CellType,
    pub coltype: ColType,
    pub col: usize,
    pub row: RowType,
    pub width: usize,
    pub attr: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct GateInfo {
    pub name: String,
    pub cells: Vec<CellInfo>,
}

pub type GateConfig = (
    String, // gate name
    //cell_name, attr_name, cell_type, col_type, col, row, width
    Vec<(String, String, String, String, usize, String, usize)>,
);

impl From<&GateConfig> for GateInfo {
    fn from(config: &GateConfig) -> Self {
        let (name, cells) = config;

        let cells: Vec<_> = cells
            .iter()
            .map(|(name, attr, celltype, coltype, col, row, width)| {
                let celltype = CellType::from(celltype.clone());
                let coltype = ColType::from(coltype.clone());
                let col = *col;
                let row = RowType::from(row.clone());
                let width = *width;

                let attr = if attr != "" { Some(attr.clone()) } else { None };

                CellInfo {
                    name: name.clone(),
                    celltype,
                    coltype,
                    col,
                    row,
                    width,
                    attr,
                }
            })
            .collect();
        Self {
            name: name.clone(),
            cells,
        }
    }
}

impl From<String> for CellType {
    fn from(celltype: String) -> Self {
        match celltype.as_str() {
            "Input" => Self::Input,
            "YInput" => Self::YInput,
            "Instance" => Self::Instance,
            "Piece" => Self::Piece,
            "Slice" => Self::Slice,
            "TopSlice" => Self::TopSlice,
            "PadSlice" => Self::PadSlice,
            "YSlice" => Self::YSlice,
            "CanonicityCheckSlice" => Self::CanonicityCheckSlice,
            "CanonicityCheckZ13" => Self::CanonicityCheckZ13,
            "CanonicityCheck" => Self::CanonicityCheck,
            "PrimeCheck" => Self::PrimeCheck,
            _ => panic!("unknown CellType: [{}]", celltype),
        }
    }
}

impl From<String> for ColType {
    fn from(coltype: String) -> Self {
        match coltype.as_str() {
            "Constant" => Self::Constant,
            "Selector" => Self::Selector,
            "Fixed" => Self::Fixed,
            "Advice" => Self::Advice,
            "Instance" => Self::Instance,
            _ => panic!("unknown ColType: [{}]", coltype),
        }
    }
}

impl From<String> for RowType {
    fn from(rowtype: String) -> Self {
        match rowtype.as_str() {
            "Cur" => Self::Cur,
            "Next" => Self::Next,
            "Prev" => Self::Prev,
            _ => panic!("unknown RowType: [{}]", rowtype),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AlgoItem {
    pub name: String, // result name
    pub desc: String,
    pub operator: String,           // add, sub, mul, poseidon
    pub operand1: (String, String), // (name, Operand type)
    pub operand2: Option<(String, String)>,
}

#[derive(Clone, Debug, Default)]
pub struct Algo {
    pub name: String,
    pub desc: String,
    pub items: Vec<(String, AlgoItem)>, //(operator, item) the first operator type should be ""
}

pub type AlgoConfig = (
    String,
    String,
    Vec<(
        String,                   //operator for previous operand, the first item shold be ""
        String,                   //result name
        String,                   //desc
        (String, String),         //operand1
        String,                   //operator, should be "" if operand2 is None
        Option<(String, String)>, //operand2
    )>,
);

impl From<&AlgoConfig> for Algo {
    fn from(config: &AlgoConfig) -> Self {
        let (name, desc, items) = config;
        let items = items
            .iter()
            .map(|(_operator, name, desc, operand1, operator, operand2)| {
                (
                    _operator.clone(),
                    AlgoItem {
                        name: name.clone(),
                        desc: desc.clone(),
                        operator: operator.clone(),
                        operand1: operand1.clone(),
                        operand2: operand2.clone(),
                    },
                )
            })
            .collect::<Vec<_>>();

        Self {
            name: name.clone(),
            desc: desc.clone(),
            items,
        }
    }
}

impl CellType {
    pub fn is_input_cell(celltype: Self) -> bool {
        celltype == Self::Input || celltype == Self::YInput
    }

    pub fn is_piece_or_slice_cell(celltype: Self) -> bool {
        return celltype == Self::Piece
            || celltype == Self::Slice
            || celltype == Self::TopSlice
            || celltype == Self::CanonicityCheckSlice;
    }

    pub fn is_z13_cell(celltype: Self) -> bool {
        celltype == Self::CanonicityCheckZ13
    }

    pub fn is_canonicity_or_prime_cell(celltype: Self) -> bool {
        return celltype == Self::CanonicityCheck || celltype == Self::PrimeCheck;
    }
}

pub(crate) type CommitInputs = Vec<(String, usize, Option<pallas::Base>, Option<pallas::Base>)>;

#[derive(Clone, Debug)]
pub enum CommitResult {
    X(Option<pallas::Base>),
    Point(Option<pallas::Point>),
}

pub trait VerifyCircuit {
    fn verify(&self) -> Result<(), Vec<VerifyFailure>>;
}
