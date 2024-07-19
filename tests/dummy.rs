use ark_std::time::{Duration, Instant};

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use ark_bls12_381::{Bls12_381, Fr};
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ff::Field;
// We'll use these interfaces to construct our circuit.
use ark_relations::{
    lc, ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
};
use ark_std::test_rng;
// For randomness (during paramgen and proof generation)
use ark_std::rand::{Rng, RngCore, SeedableRng};

use sigma0_polymath::transcript::MerlinFieldTranscript;

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

#[test]
fn test_dummy_polymath() {
    type Polymath = sigma0_polymath::Polymath<Bls12_381, MerlinFieldTranscript<Fr>>;

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    println!("Creating parameters...");

    // Create parameters for our circuit
    let (pk, vk) = {
        let c = DummyCircuit::<Fr> { a: None, b: None };

        Polymath::setup(c, &mut rng).unwrap()
    };

    println!("Creating proofs...");

    // Let's benchmark stuff!
    const SAMPLES: u32 = 50;
    let mut total_proving = Duration::new(0, 0);
    let mut total_verifying = Duration::new(0, 0);

    for _ in 0..SAMPLES {
        // Generate random factors and compute the product
        let a = rng.gen();
        let b = rng.gen();
        let product = a * b; // this is the public input

        let start = Instant::now();

        // Create an instance of our circuit (with the
        // witness)
        let circuit = DummyCircuit {
            a: Some(a),
            b: Some(b),
        };

        let proof = Polymath::prove(&pk, circuit, &mut rng).unwrap();
        total_proving += start.elapsed();

        let start = Instant::now();
        assert!(Polymath::verify(&vk, &[product], &proof).unwrap());
        total_verifying += start.elapsed();
    }
    let proving_avg = total_proving / SAMPLES;
    let proving_avg =
        proving_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (proving_avg.as_secs() as f64);

    let verifying_avg = total_verifying / SAMPLES;
    let verifying_avg =
        verifying_avg.subsec_nanos() as f64 / 1_000_000_000f64 + (verifying_avg.as_secs() as f64);

    println!("Average proving time: {:?} seconds", proving_avg);
    println!("Average verifying time: {:?} seconds", verifying_avg);
}
