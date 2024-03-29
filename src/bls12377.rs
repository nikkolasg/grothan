use super::poseidon;
use super::OpMode;
use ark_ec::bls12;
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
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::{poseidon::constraints::PoseidonSpongeVar, CryptographicSponge};
use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use eyre::{Result, WrapErr};
use std::ops::MulAssign;
struct FqCircuit<I, IV>
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

impl<I, IV> FqCircuit<I, IV>
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
        let mut bg = I::G1Projective::prime_subgroup_generator();
        let mut cg = I::G1Projective::prime_subgroup_generator();
        ag.mul_assign(a);
        bg.mul_assign(b);
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

impl<I, IV> ConstraintSynthesizer<I::Fq> for FqCircuit<I, IV>
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
            OpMode::GtMul => {
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
            OpMode::GtAdd => {
                // Free because of addition but record it for history
                let a = IV::GTVar::new_witness(ns!(cs, "at"), || Ok(self.at))?;
                let b = IV::GTVar::new_witness(ns!(cs, "bt"), || Ok(self.bt))?;
                let exp = IV::GTVar::new_witness(ns!(cs, "at"), || Ok(self.ct))?;
                let c = a * b;
                c.enforce_equal(&exp)?;
            }
            OpMode::Equality => {
                let ct = IV::GTVar::new_witness(ns!(cs, "CT"), || Ok(self.ct))?;
                ct.enforce_equal(&ct)?;
            }
            OpMode::HashGT(n) => {
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
            OpMode::G2Mul => {
                let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.bg))?;
                let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
                    &self.c.into_repr().to_bits_le(),
                ))
                .unwrap();
                let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
                let bits_c = c.to_bits_le()?;
                bg.scalar_mul_le(bits_c.iter())?;
            }

            OpMode::NNAFieldAddOverFq => {
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
            OpMode::NNAFieldMulOverFq => {
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
            _ => panic!("unsupported operation on bls12377 circuit"),
        };
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum NNAMode {
    Add,
    Mul,
}

struct NNACircuit<F: PrimeField, CF: PrimeField> {
    e1: F,
    e2: F,
    e3: F,
    m: NNAMode,
    _f1: PhantomData<F>,
    _f2: PhantomData<CF>,
}

impl<F: PrimeField, CF: PrimeField> NNACircuit<F, CF> {
    fn new(m: NNAMode) -> Self {
        let e1 = F::rand(&mut rand::thread_rng());
        let e2 = F::rand(&mut rand::thread_rng());
        let e3 = e1 * e2;
        Self {
            m,
            _f1: PhantomData,
            _f2: PhantomData,
            e1,
            e2,
            e3,
        }
    }
}

impl<F: PrimeField, CF: PrimeField> ConstraintSynthesizer<CF> for NNACircuit<F, CF> {
    fn generate_constraints(self, cs: ConstraintSystemRef<CF>) -> Result<(), SynthesisError> {
        let nna_e1 = NonNativeFieldVar::<F, CF>::new_witness(
            ark_relations::ns!(cs, "nna_circuit_e1"),
            || Ok(self.e1.clone()),
        )?;
        let nna_e2 = NonNativeFieldVar::<F, CF>::new_witness(
            ark_relations::ns!(cs, "nna_circuit_e2"),
            || Ok(self.e2.clone()),
        )?;

        match self.m {
            NNAMode::Add => {
                let res_e3 = nna_e1 + nna_e2;
            }
            NNAMode::Mul => {
                let res_e3 = nna_e1 * nna_e2;
            }
        }
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
    fn bench_381_in_377() {
        for mode in vec![NNAMode::Add, NNAMode::Mul].into_iter() {
            let cs = ConstraintSystem::<Fr>::new_ref();
            NNACircuit::<ark_bls12_381::Fr, Fr>::new(mode.clone())
                .generate_constraints(cs.clone())
                .unwrap();
            assert!(cs.is_satisfied().unwrap());
            println!("NNA Mode {:?} : {}", mode, cs.num_constraints());
        }
    }

    #[test]
    fn bench_bls12377() {
        let mut rng = ark_std::test_rng();
        for mode in vec![
            OpMode::Mul,
            OpMode::GtMul,
            OpMode::GtAdd,
            OpMode::Equality,
            OpMode::HashGT(7),
            OpMode::MillerLoop(1),
            OpMode::MillerLoop(45),
            OpMode::FinalExp,
            OpMode::Pairing,
            OpMode::G1Mul,
            OpMode::G2Mul,
            OpMode::NNAFieldAddOverFq,
            OpMode::NNAFieldMulOverFq,
            OpMode::NNAHash(3),
        ] {
            println!("GT operation {:?}", mode);
            let cs = ConstraintSystem::<<I as PairingEngine>::Fq>::new_ref();
            FqCircuit::<I, IV>::new(&mut rng, mode, poseidon::get_bls12377_fq_params(2))
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
