use std::{marker::PhantomData, os::unix::thread};

use ark_ec::PairingEngine;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintLayer};

use super::OpMode;

struct Circuit<E: PairingEngine> {
    mode: OpMode,
    _p: PhantomData<E>
} 

impl<E: PairingEngine> ConstraintSynthesizer<E::Fr> for Circuit<E> {
    fn generate_constraints(self, cs: ark_relations::r1cs::ConstraintSystemRef<E::Fr>) -> ark_relations::r1cs::Result<()> {
        match self.mode {
            OpMode::NNAG1Mul => {
                let scalar = E::Fr::rand(&mut thread_rng());
                let point = E::G1Affine::rand(&mut thread_rng());
            },
            _ => panic!("unsupported mode"),
        } 
    }
}