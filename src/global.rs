use ff::PrimeField;
use group::GroupEncoding;
use halo2_proofs::arithmetic::CurveExt;
use lazy_static::lazy_static;
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::pallas;
use std::collections::HashMap;
use std::sync::Mutex;

use super::base;
use super::types::*;
use crate::domains::*;

type MapGenerator = HashMap<String, Option<TGenerator>>;
type MapZsUs = HashMap<String, Option<TZsUs>>;

lazy_static! {
    static ref GENERATOR_Q_MAP: Mutex<MapGenerator> = Mutex::new(HashMap::new());
    static ref GENERATOR_R_MAP: Mutex<MapGenerator> = Mutex::new(HashMap::new());
    static ref ZSUS_MAP: Mutex<MapZsUs> = Mutex::new(HashMap::new());
    static ref ZSUS_MAP_SHORT: Mutex<MapZsUs> = Mutex::new(HashMap::new());
    static ref DOMAINS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
    static ref BASE_POINT_MAP: Mutex<HashMap<String, [u8; 32]>> = Mutex::new(HashMap::new());
    static ref FIXED_BASE_FULLS: Mutex<HashMap<String, Option<DomainFullWidth>>> =
        Mutex::new(HashMap::new());
    static ref FIXED_POINT_BASE_FIELDS: Mutex<HashMap<String, Option<DomainBaseField>>> =
        Mutex::new(HashMap::new());
    static ref FIXED_POINT_SHORTS: Mutex<HashMap<String, Option<DomainShort>>> =
        Mutex::new(HashMap::new());
}

pub fn config_fixedbasefull(name: &str, domain: &str, num_windows: usize) {
    FIXED_BASE_FULLS.lock().unwrap().insert(
        name.to_string(),
        Some(DomainFullWidth {
            domain: domain.to_string(),
            num_windows: num_windows,
        }),
    );
}

pub fn get_fixedbasefull(name: &str) -> Option<DomainFullWidth> {
    let map = FIXED_BASE_FULLS.lock().unwrap();
    let v = map.get(name);
    match v {
        Some(v) => v.clone(),
        None => None,
    }
}

pub fn config_fixedpointbasefield(name: &str, domain: &str, num_windows: usize) {
    FIXED_POINT_BASE_FIELDS.lock().unwrap().insert(
        name.to_string(),
        Some(DomainBaseField {
            domain: domain.to_string(),
            num_windows: num_windows,
        }),
    );
}

pub fn get_fixedpointbasefield(name: &str) -> Option<DomainBaseField> {
    let map = FIXED_POINT_BASE_FIELDS.lock().unwrap();
    let v = map.get(name);
    match v {
        Some(v) => v.clone(),
        None => None,
    }
}

pub fn config_fixedpointshort(name: &str, domain: &str, num_windows_short: usize) {
    FIXED_POINT_SHORTS.lock().unwrap().insert(
        name.to_string(),
        Some(DomainShort {
            domain: domain.to_string(),
            num_windows_short: num_windows_short,
        }),
    );
}

pub fn get_fixedpointshort(name: &str) -> Option<DomainShort> {
    let map = FIXED_POINT_SHORTS.lock().unwrap();
    let v = map.get(name);
    match v {
        Some(v) => v.clone(),
        None => None,
    }
}

pub fn config_generator_q(domain: &str, generator: &Option<TGenerator>) {
    GENERATOR_Q_MAP
        .lock()
        .unwrap()
        .insert(domain.to_string(), generator.clone());
}

pub fn config_generator_r(domain: &str, generator: &Option<TGenerator>) {
    GENERATOR_R_MAP
        .lock()
        .unwrap()
        .insert(domain.to_string(), generator.clone());
}

pub fn config_generator(domain: &str, generator: &Option<TGenerator>) {
    config_generator_r(domain, generator)
}

pub(crate) fn get_generator_q(domain: &str) -> Option<TGenerator> {
    let map = GENERATOR_Q_MAP.lock().unwrap();
    let generator = map.get(domain);
    match generator {
        Some(v) => *v,
        None => None,
    }
}

pub(crate) fn get_generator_r(domain: &str) -> Option<TGenerator> {
    let map = GENERATOR_R_MAP.lock().unwrap();
    let generator = map.get(domain);
    match generator {
        Some(v) => *v,
        None => None,
    }
}

pub fn is_exist_zs_and_us(domain: &str) -> bool {
    ZSUS_MAP.lock().unwrap().contains_key(domain)
}

pub fn is_exist_zs_and_us_short(domain: &str) -> bool {
    ZSUS_MAP_SHORT.lock().unwrap().contains_key(domain)
}

pub fn config_zs_and_us(domain: &str, zs_and_us: &Option<TZsUs>) {
    ZSUS_MAP
        .lock()
        .unwrap()
        .insert(domain.to_string(), zs_and_us.clone());
}

pub fn config_zs_and_us_short(domain: &str, zs_and_us: &Option<TZsUs>) {
    ZSUS_MAP_SHORT
        .lock()
        .unwrap()
        .insert(domain.to_string(), zs_and_us.clone());
}

pub(crate) fn get_zs_and_us(domain: &str) -> Option<TZsUs> {
    let map = ZSUS_MAP.lock().unwrap();
    let zs_and_us = map.get(domain);
    match zs_and_us {
        Some(v) => v.clone(),
        None => None,
    }
}

pub(crate) fn get_zs_and_us_short(domain: &str) -> Option<TZsUs> {
    let map = ZSUS_MAP_SHORT.lock().unwrap();
    let zs_and_us = map.get(domain);
    match zs_and_us {
        Some(v) => v.clone(),
        None => None,
    }
}

pub(crate) fn generator(domain: &str) -> pallas::Affine {
    let generator = get_generator_r(domain);
    if generator.is_none() {
        base::generator_r(&domain)
    } else {
        let generator = generator.unwrap();
        pallas::Affine::from_xy(
            pallas::Base::from_repr(generator.0).unwrap(),
            pallas::Base::from_repr(generator.1).unwrap(),
        )
        .unwrap()
    }
}

pub(crate) fn u(domain: &str, num_windows: usize) -> TUs {
    if !is_exist_zs_and_us(domain) {
        let basepoint = generator(domain);
        let zs_and_us = base::get_zs_and_us(basepoint, num_windows);
        let zs_and_us = base::convert_zs_us(zs_and_us.unwrap());
        config_zs_and_us(domain, &Some(zs_and_us));
    }

    let zs_and_us = get_zs_and_us(domain).unwrap();
    zs_and_us.1
}

pub(crate) fn u_short(domain: &str, num_windows_short: usize) -> TUs {
    if !is_exist_zs_and_us_short(domain) {
        let basepoint = generator(domain);
        let zs_and_us_short = base::get_zs_and_us(basepoint, num_windows_short);
        let zs_and_us_short = base::convert_zs_us(zs_and_us_short.unwrap());
        config_zs_and_us_short(domain, &Some(zs_and_us_short));
    }

    let zs_and_us_short = get_zs_and_us_short(domain).unwrap();
    zs_and_us_short.1
}

pub(crate) fn z(domain: &str, num_windows: usize) -> TZs {
    if !is_exist_zs_and_us(domain) {
        let basepoint = generator(domain);
        let zs_and_us = base::get_zs_and_us(basepoint, num_windows);
        let zs_and_us = base::convert_zs_us(zs_and_us.unwrap());
        config_zs_and_us(domain, &Some(zs_and_us));
    }

    let zs_and_us = get_zs_and_us(domain).unwrap();
    zs_and_us.0
}

pub(crate) fn z_short(domain: &str, num_windows_short: usize) -> TZs {
    if !is_exist_zs_and_us_short(domain) {
        let basepoint = generator(domain);
        let zs_and_us_short = base::get_zs_and_us(basepoint, num_windows_short);
        let zs_and_us_short = base::convert_zs_us(zs_and_us_short.unwrap());
        config_zs_and_us_short(domain, &Some(zs_and_us_short));
    }

    let zs_and_us_short = get_zs_and_us_short(domain).unwrap();
    zs_and_us_short.0
}

pub fn config_domain_name(domain: &str, value: &str) {
    DOMAINS
        .lock()
        .unwrap()
        .insert(domain.to_string(), value.to_string());
}

pub(crate) fn get_domain_name(domain: &str) -> String {
    let domains = DOMAINS.lock().unwrap();
    if !domains.contains_key(domain) {
        return domain.to_string();
    }
    domains.get(&domain.to_string()).unwrap().to_string()
}

pub fn config_base_point(name: &str, bp: &[u8; 32]) {
    BASE_POINT_MAP
        .lock()
        .unwrap()
        .insert(name.to_string(), bp.clone());
}

pub(crate) fn get_base_point(name: &str, h: &[u8; 1]) -> [u8; 32] {
    let mut map = BASE_POINT_MAP.lock().unwrap();
    if !map.contains_key(name) {
        let bp = pallas::Point::hash_to_curve(name)(h).to_bytes();
        map.insert(name.to_string(), bp.clone());
    }

    map[name]
}
