// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{test_rng, UniformRand};
// For randomness (during paramgen and proof generation)
use ark_std::rand::{RngCore, SeedableRng};
use sigma0_polymath::{
    keccak256::Keccak256Transcript, merlin::MerlinFieldTranscript, Polymath, Transcript,
};

struct DummyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;

        let c = self.a.and_then(|a| self.b.map(|b| a * b));
        let c = cs.new_input_variable(|| c.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)
    }
}

fn run_dummy_polymath<E, T>()
where
    E: Pairing,
    T: Transcript<Challenge = E::ScalarField>,
{
    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("Creating parameters...");

    // Create parameters for our circuit
    let (pk, vk) = {
        let c = DummyCircuit::<E::ScalarField> { a: None, b: None };

        Polymath::<E, T>::setup(c, &mut rng).unwrap()
    };

    // Generate random factors and compute the product
    let a = E::ScalarField::rand(&mut rng);
    let b = E::ScalarField::rand(&mut rng);
    let product = a * b; // this is the public input

    // Create an instance of our circuit (with the witness)
    let circuit = DummyCircuit {
        a: Some(a),
        b: Some(b),
    };
    println!("Creating proofs...");

    let proof = Polymath::<E, T>::prove(&pk, circuit, &mut rng).unwrap();
    println!("Verify proofs...");
    assert!(
        Polymath::<E, T>::verify(&vk, &[product], &proof).unwrap(),
        "Proof failed"
    );
}

#[test]
fn test_dummy_polymath() {
    run_dummy_polymath::<Bls12_381, MerlinFieldTranscript<Fr>>();
    run_dummy_polymath::<Bls12_381, Keccak256Transcript<Fr>>();
}
