#[macro_use]
extern crate json;
#[macro_use]
extern crate lazy_static;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
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
use std::ops::MulAssign;
mod poseidon;

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum OpMode {
    Mul,         // GT * GT
    ScalarMul,   // Fr * GT
    Equality,    // GT == GT
    Hash(usize), // H(number of gt elements)
    //G1Mul,       // Fr * G1
    Pairing, // e(G1,G2)
}

struct GTCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    c: I::Fr,
    at: I::Fqk,
    bt: I::Fqk,
    ct: I::Fqk,
    t: I::Fqk,
    ag: I::G1Projective,
    bg: I::G2Projective,
    mode: OpMode,
    poseidon_params: PoseidonParameters<I::Fq>,
    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}

impl<I, IV> GTCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng + CryptoRng>(
        mut rng: &mut R,
        mode: OpMode,
        params: PoseidonParameters<I::Fq>,
    ) -> Self {
        // AT = e(aG,G)
        // BT = e(bG,G)
        // CT = AT * BT = e(G,G)^{a+b}
        let a = I::Fr::rand(&mut rng);
        let b = I::Fr::rand(&mut rng);
        let c = a + b;
        let mut ag = I::G1Projective::prime_subgroup_generator();
        ag.mul_assign(a);
        let mut bg = I::G1Projective::prime_subgroup_generator();
        bg.mul_assign(b);
        let mut cg = I::G1Projective::prime_subgroup_generator();
        cg.mul_assign(c);
        let at = I::pairing(ag, I::G2Projective::prime_subgroup_generator());
        let bt = I::pairing(bg, I::G2Projective::prime_subgroup_generator());
        let abt = I::pairing(cg, I::G2Projective::prime_subgroup_generator());
        let t = I::pairing(
            I::G1Projective::prime_subgroup_generator(),
            I::G2Projective::prime_subgroup_generator(),
        );
        // CT = GT^c = GT^{a+b} = GT^a * GT^b
        let ct = t.pow(&c.into_repr());
        assert_eq!(abt, ct);
        let ct2 = t.pow(&a.into_repr()) * t.pow(&b.into_repr());
        assert_eq!(ct, ct2);
        Self {
            mode: mode,
            c: c,
            at: at,
            bt: bt,
            ct: ct,
            ag: ag,
            bg: I::G2Projective::prime_subgroup_generator(),
            t: t,
            poseidon_params: params,
            _iv: PhantomData,
            _i: PhantomData,
        }
    }
}

impl<I, IV> ConstraintSynthesizer<I::Fq> for GTCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
    IV::GTVar: ToConstraintFieldGadget<I::Fq>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<I::Fq>) -> Result<(), SynthesisError> {
        let at = IV::GTVar::new_witness(ns!(cs, "a"), || Ok(self.at))?;
        let bt = IV::GTVar::new_witness(ns!(cs, "b"), || Ok(self.bt))?;
        let ct = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
        match self.mode {
            OpMode::Mul => {
                let exp = at * bt;
                ct.enforce_equal(&exp)?;
            }
            OpMode::ScalarMul => {
                let exp = IV::GTVar::new_witness(ns!(cs, "T"), || Ok(self.t))?;
                let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
                    &self.c.into_repr().to_bits_le(),
                ))
                .unwrap();
                let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
                let bits_c = c.to_bits_le()?;
                let exp = exp.pow_le(&bits_c)?;
                ct.enforce_equal(&exp)?;
            }
            OpMode::Equality => {
                ct.enforce_equal(&ct)?;
            }
            OpMode::Hash(n) => {
                let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);
                for i in 0..n {
                    sponge.absorb(&at.to_constraint_field()?);
                }
                sponge.squeeze_field_elements(1)?.remove(0);
            }
            OpMode::Pairing => {} /*OpMode::G1Mul => {*/
                                  /*let exp = IV::GTVar::new_witness(ns!(cs, "T"), || Ok(self.t))?;*/
                                  /*let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(*/
                                  /*&self.c.into_repr().to_bits_le(),*/
                                  /*))*/
                                  /*.unwrap();*/
                                  /*let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;*/
                                  /*let bits_c = c.to_bits_le()?;*/
                                  /*}*/
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn gt_size() {
        let mut rng = ark_std::test_rng();
        for mode in vec![
            OpMode::Mul,
            OpMode::ScalarMul,
            OpMode::Equality,
            OpMode::Hash(7),
        ] {
            println!("GT operation {:?}", mode);
            let cs = ConstraintSystem::<<I as PairingEngine>::Fq>::new_ref();
            GTCircuit::<I, IV>::new(&mut rng, mode, poseidon::get_bls12377_fq_params(2))
                .generate_constraints(cs.clone())
                .unwrap();
            assert!(cs.is_satisfied().unwrap());

            println!("\t-Num constraints: {}", cs.num_constraints());
        }

        /* let (pk,vk) = Groth16::setup(GTCircuit::<I,IV>::new(), &mut rng).unwrap();*/
        //let opvk = Groth16::<O>::process_vk(&ovk).unwrap();
        //let circuit = GTCircuit::<I, IV>::new();
        /*let proof = Groth16::<O>::prove(&pk, circuit, &mut rng).unwrap();*/
    }
}
