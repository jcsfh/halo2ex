use pasta_curves::vesta;

use halo2_proofs::{
    plonk::{self, SingleVerifier},
    poly,
    transcript::{Blake2bRead, Blake2bWrite},
};

use memuse::DynamicUsage;
use rand::RngCore;

use super::base::*;
use super::ic::*;

#[derive(Debug)]
pub struct VerifyingKey {
    params: poly::commitment::Params<vesta::Affine>,
    vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    pub fn build<T: Default + Clone + ICConfig>(k: u32) -> Self {
        let params = poly::commitment::Params::new(k);
        let circuit: ICCircuit<T> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();

        VerifyingKey { params, vk }
    }
}

#[derive(Debug)]
pub struct ProvingKey {
    params: poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl ProvingKey {
    pub fn build<T: Default + Clone + ICConfig>(k: u32) -> Self {
        let params = poly::commitment::Params::new(k);
        let circuit: ICCircuit<T> = Default::default();

        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();

        ProvingKey { params, pk }
    }
}

#[derive(Debug, Clone)]
pub struct Proof(Vec<u8>);

impl AsRef<[u8]> for Proof {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl DynamicUsage for Proof {
    fn dynamic_usage(&self) -> usize {
        self.0.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.0.dynamic_usage_bounds()
    }
}

impl Proof {
    pub fn create<T: Default + Clone + ICConfig>(
        pk: &ProvingKey,
        circuits: &[ICCircuit<T>],
        instances: &[Instance<T>],
        mut rng: impl RngCore,
    ) -> Result<Self, plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        plonk::create_proof(
            &pk.params,
            &pk.pk,
            circuits,
            &instances,
            &mut rng,
            &mut transcript,
        )?;
        Ok(Proof(transcript.finalize()))
    }

    pub fn verify<T: ICConfig>(
        &self,
        vk: &VerifyingKey,
        instances: &[Instance<T>],
    ) -> Result<(), plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2_instance()).collect();
        let instances: Vec<Vec<_>> = instances
            .iter()
            .map(|i| i.iter().map(|c| &c[..]).collect())
            .collect();
        let instances: Vec<_> = instances.iter().map(|i| &i[..]).collect();

        let strategy = SingleVerifier::new(&vk.params);
        let mut transcript = Blake2bRead::init(&self.0[..]);
        plonk::verify_proof(&vk.params, &vk.vk, strategy, &instances, &mut transcript)
    }

    pub fn new(bytes: Vec<u8>) -> Self {
        Proof(bytes)
    }

    pub fn get_expected_proof_size<T: Default + Clone + ICConfig>(
        circuits: &[ICCircuit<T>],
        instances: &[Instance<T>],
        k: u32,
    ) -> usize {
        let circuit_cost = halo2_proofs::dev::CircuitCost::<pasta_curves::vesta::Point, _>::measure(
            k as usize,
            &circuits[0],
        );
        usize::from(circuit_cost.proof_size(instances.len()))
    }
}

#[cfg(feature = "dev-graph")]
pub fn print_ic_circuit<T: Default + Clone + ICConfig>(title: &str, k: u32) {
    use plotters::prelude::*;

    let root = BitMapBackend::new(&format!("{}.png", title), (1024, 768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root.titled(title, ("sans-serif", 60)).unwrap();

    let circuit = ICCircuit::<T>::default();

    halo2_proofs::dev::CircuitLayout::default()
        .show_labels(false)
        .view_height(0..(1 << k))
        .render(k, &circuit, &root)
        .unwrap();
}
