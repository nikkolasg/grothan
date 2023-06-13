#[macro_use]
extern crate json;
#[macro_use]
extern crate lazy_static;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    pairing::PairingVar,
    ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Field, SynthesisError},
};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::{poseidon::PoseidonParameters, Absorb};
use ark_sponge::{
    poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    CryptographicSponge,
};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use eyre::{Result, WrapErr};
use std::ops::MulAssign;
mod bls12377;
mod bls12381;
mod poseidon;

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum OpMode {
    Mul,   // GT * GT
    GtMul, // Fr * GT
    GtAdd, // GT + GT
    Equality,          // GT == GT
    HashGT(usize),     // H(number of gt elements)
    HashFr(usize),     // H(number of fr elements)
    NNAHash(usize),    // H(number of NNA field) -> NNA field
    G1Mul,             // Fr * G1
    G2Mul,             // Fr * G2
    MillerLoop(usize), // miller(G1,G2)
    FinalExp,          // e(g1,g2)^r
    Pairing,           // full pairing
    NNAFieldAddOverFq, // Non native field arithmetic Fr addition in Fq
    NNAFieldMulOverFq, // Non native field arithmetic Fr multiplication in Fq
    NNAG1Mul,          // s*G in non native
    NNAFielAddOverF2,  // Non native field arithmetic Fr over a different unrelated field F2
                       // e.g. it can be bls12-381's Fr done on bls12-377's Fr
}
