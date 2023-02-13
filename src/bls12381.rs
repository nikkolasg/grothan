use super::OpMode;
use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::PoseidonParameters;
use ark_std::UniformRand;
use std::{marker::PhantomData, os::unix::thread};
struct Circuit<E: PairingEngine, NNA: PrimeField> {
    mode: OpMode,
    p: PoseidonParameters<E::Fr>,
    _p: PhantomData<E>,
    _f: PhantomData<NNA>,
}

impl<E: PairingEngine, NNA: PrimeField> ConstraintSynthesizer<E::Fr> for Circuit<E, NNA> {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<E::Fr>,
    ) -> ark_relations::r1cs::Result<()> {
        match self.mode {
            OpMode::NNAHash(n) => {
                let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.p);
                let cv = NonNativeFieldVar::<NNA, E::Fr>::new_witness(
                    ark_relations::ns!(cs, "nna hash"),
                    || Ok(NNA::rand(&mut rand::thread_rng())),
                )
                .unwrap();
                for i in 0..n {
                    sponge.absorb(&cv.to_constraint_field()?);
                }
                sponge.squeeze_nonnative_field_elements::<E::Fr>(1);
            }
            _ => panic!("unsupported mode"),
        }
        Ok(())
    }
}
