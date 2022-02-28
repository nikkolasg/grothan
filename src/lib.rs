use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, BitIteratorLE, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    pairing::PairingVar,
    ToBitsGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Field, SynthesisError},
};
use ark_std::marker::PhantomData;
use ark_std::rand::{CryptoRng, Rng};
use ark_std::UniformRand;
use std::ops::MulAssign;

#[derive(Debug, Clone)]
enum OpMode {
    Mul,       // GT * GT
    ScalarMul, // Fr * GT
    Equality,  // GT == GT
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
    mode: OpMode,
    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}

impl<I, IV> GTCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    pub fn new<R: Rng + CryptoRng>(mut rng: &mut R, mode: OpMode) -> Self {
        // AT = e(aG,G)
        // BT = e(bG,G)
        // CT = AT * BT = e(G,G)^{a+b}
        let a = I::Fr::rand(&mut rng);
        let b = I::Fr::rand(&mut rng);
        let c = a + b;
        let mut A = I::G1Projective::prime_subgroup_generator();
        A.mul_assign(a);
        let mut B = I::G1Projective::prime_subgroup_generator();
        B.mul_assign(b);
        let mut C = I::G1Projective::prime_subgroup_generator();
        C.mul_assign(c);
        let AT = I::pairing(A, I::G2Projective::prime_subgroup_generator());
        let BT = I::pairing(B, I::G2Projective::prime_subgroup_generator());
        let ABT = I::pairing(C, I::G2Projective::prime_subgroup_generator());
        let T = I::pairing(
            I::G1Projective::prime_subgroup_generator(),
            I::G2Projective::prime_subgroup_generator(),
        );
        // CT = GT^c = GT^{a+b} = GT^a * GT^b
        let CT = T.pow(&c.into_repr());
        assert_eq!(ABT, CT);
        let CT2 = T.pow(&a.into_repr()) * T.pow(&b.into_repr());
        assert_eq!(CT, CT2);
        Self {
            mode: mode,
            c: c,
            at: AT,
            bt: BT,
            ct: CT,
            t: T,
            _iv: PhantomData,
            _i: PhantomData,
        }
    }
}

impl<I, IV> ConstraintSynthesizer<I::Fq> for GTCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
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
                let mut exp = IV::GTVar::new_witness(ns!(cs, "T"), || Ok(self.t))?;
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
            _ => {
                panic!("aie");
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::{constraints::PairingVar as IV, Bls12_377 as I, Fr};
    use ark_bw6_761::BW6_761 as O;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

    #[test]
    fn gt_size() {
        let mut rng = ark_std::test_rng();
        for mode in vec![OpMode::Mul, OpMode::ScalarMul, OpMode::Equality] {
            println!("GT operation {:?}", mode);
            let cs = ConstraintSystem::<<I as PairingEngine>::Fq>::new_ref();
            GTCircuit::<I, IV>::new(&mut rng, mode)
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
