pub use halo2_gadgets;
pub use pasta_curves;

#[macro_use]
pub mod base;
pub mod consts;
pub mod domains;
pub mod global;
pub(crate) mod halo2api;
pub mod types;

pub mod primitives {
    pub mod keys;
    pub mod nippoint;
    pub mod utils;

    pub mod commitment;
    pub mod nullifier;
    pub mod tree;
    pub mod value;
}

pub mod sinsemilla {
    pub mod circuit;
    pub mod config;
}

pub mod circuit {
    pub(crate) mod algo;
    pub mod base;
    pub mod ic;
    pub mod proof;
    pub(crate) mod synthesize;
}

#[cfg(test)]
pub mod test {
    pub mod sinsemilla {
        pub mod commit;
        pub(crate) mod constants;
    }

    pub mod ic {
        pub mod circuit;
        pub mod constants {
            pub(crate) mod auth_g;
            pub(crate) mod commit;
            pub(crate) mod merklecrh;
            pub(crate) mod netcv;
            pub(crate) mod nullifier_k;
            pub(crate) mod short_commit;
            pub(crate) mod valuecommit_r;
            pub(crate) mod valuecommit_v;
        }
    }
}
