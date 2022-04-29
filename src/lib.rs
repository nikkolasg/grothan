#[macro_use]
extern crate json;
#[macro_use]
extern crate lazy_static;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
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
mod poseidon;

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum OpMode {
    Mul,               // GT * GT
    ScalarMul,         // Fr * GT
    Equality,          // GT == GT
    Hash(usize),       // H(number of gt elements)
    G1Mul,             // Fr * G1
    MillerLoop(usize), // miller(G1,G2)
    FinalExp,          // e(g1,g2)^r
    Pairing,           // full pairing
    NNAFieldAdd,       // Non native field arithmetic Fr addition in Fq
    NNAFieldMul,       // Non native field arithmetic Fr multiplication in Fq
    NNAHash(usize),    // H(number of NNA field) -> NNA field
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
    miller_out: I::Fqk,
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
        let miller_out = I::miller_loop([&(
            ag.into_affine().into(),
            I::G2Affine::prime_subgroup_generator().into(),
        )]);
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
            miller_out: miller_out,
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
        match self.mode {
            OpMode::Mul => {
                let ct = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
                let at = IV::GTVar::new_witness(ns!(cs, "a"), || Ok(self.at))?;
                let bt = IV::GTVar::new_witness(ns!(cs, "b"), || Ok(self.bt))?;
                let exp = at * bt;
                ct.enforce_equal(&exp)?;
            }
            OpMode::ScalarMul => {
                let ct = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
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
                let ct = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
                ct.enforce_equal(&ct)?;
            }
            OpMode::Hash(n) => {
                let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);
                let at = IV::GTVar::new_witness(ns!(cs, "a"), || Ok(self.at))?;
                for i in 0..n {
                    sponge.absorb(&at.to_constraint_field()?);
                }
                sponge.squeeze_field_elements(1)?.remove(0);
            }
            OpMode::NNAHash(n) => {
                let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.poseidon_params);
                let cv = NonNativeFieldVar::<I::Fr, I::Fq>::new_witness(
                    ark_relations::ns!(cs, "share_nonnative"),
                    || Ok(self.c.clone()),
                )?;
                for i in 0..n {
                    sponge.absorb(&cv.to_constraint_field()?);
                }
                sponge.squeeze_nonnative_field_elements::<I::Fr>(1);
            }
            OpMode::MillerLoop(n) => {
                let mut ps = Vec::new();
                let mut qs = Vec::new();
                for _ in 0..n {
                    let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.bg))?;
                    let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.ag))?;
                    let pag = IV::prepare_g1(&ag)?;
                    let pbg = IV::prepare_g2(&bg)?;
                    ps.push(pag);
                    qs.push(pbg);
                }
                IV::miller_loop(&ps, &qs)?;
            }
            OpMode::FinalExp => {
                let m = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
                let at = IV::GTVar::new_witness(ns!(cs, "a"), || Ok(self.at))?;
                IV::final_exponentiation(&at)?;
            }
            OpMode::Pairing => {
                let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.ag))?;
                let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.bg))?;
                let pag = IV::prepare_g1(&ag)?;
                let pbg = IV::prepare_g2(&bg)?;
                IV::pairing(pag, pbg)?;
            }
            OpMode::G1Mul => {
                let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.ag))?;
                let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
                    &self.c.into_repr().to_bits_le(),
                ))
                .unwrap();
                let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
                let bits_c = c.to_bits_le()?;
                ag.scalar_mul_le(bits_c.iter())?;
            }
            OpMode::NNAFieldAdd => {
                let cv = NonNativeFieldVar::<I::Fr, I::Fq>::new_witness(
                    ark_relations::ns!(cs, "share_nonnative"),
                    || Ok(self.c.clone()),
                )?;
                let cv2 = NonNativeFieldVar::<I::Fr, I::Fq>::new_witness(
                    ark_relations::ns!(cs, "share_nonnative"),
                    || Ok(self.c),
                )?;
                cv + cv2;
            }
            OpMode::NNAFieldMul => {
                let cv = NonNativeFieldVar::<I::Fr, I::Fq>::new_witness(
                    ark_relations::ns!(cs, "share_nonnative"),
                    || Ok(self.c.clone()),
                )?;
                let cv2 = NonNativeFieldVar::<I::Fr, I::Fq>::new_witness(
                    ark_relations::ns!(cs, "share_nonnative"),
                    || Ok(self.c),
                )?;
                cv * cv2;
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::{
        constraints::PairingVar as IV, Bls12_377 as I, Fr, G1Projective as G1, G2Projective as G2,
    };
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use ark_std::One;

    #[test]
    fn sizes() {
        let g1 = G1::prime_subgroup_generator();
        print_size(g1, "size of g1");
        let g2 = G2::prime_subgroup_generator();
        let gt = <I as PairingEngine>::pairing::<G1, G2>(
            g1.into_affine().into(),
            g2.into_affine().into(),
        );
        print_size(g2, "size of g2");
        print_size(gt, "size of GT");
        print_size(Fr::one(), "size of Fr");
        /*for (s, topic) in elements {*/
        /*print_size(s, topic).unwrap();*/
        /*}*/
    }

    fn print_size<S: CanonicalSerialize>(s: S, n: &str) -> Result<()> {
        let mut v = Vec::new();
        s.serialize(&mut v)?;
        println!("{} -> {} bytes", n, v.len());
        Ok(())
    }

    #[test]
    fn bench() {
        let mut rng = ark_std::test_rng();
        for mode in vec![
            OpMode::Mul,
            OpMode::ScalarMul,
            OpMode::Equality,
            OpMode::Hash(7),
            OpMode::MillerLoop(1),
            OpMode::MillerLoop(45),
            OpMode::FinalExp,
            OpMode::Pairing,
            OpMode::G1Mul,
            OpMode::NNAFieldAdd,
            OpMode::NNAFieldMul,
            OpMode::NNAHash(3),
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
