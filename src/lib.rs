//! An implementation of the [`Polymath`] zkSNARK.
//!
//! [`Polymath`]: https://eprint.iacr.org/2024/916.pdf
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(
    unused,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    missing_docs
)]
#![allow(clippy::many_single_char_names, clippy::op_ref)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate ark_std;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Polymath zkSNARK construction.
pub mod generator;

/// Create proofs for the Polymath zkSNARK construction.
pub mod prover;

/// Verify proofs for the Polymath zkSNARK construction.
pub mod verifier;

#[cfg(test)]
mod test;

pub use self::data_structures::*;
pub use self::verifier::*;

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;
use ark_std::{marker::PhantomData, vec::Vec};

/// The [[Polymath]](https://eprint.iacr.org/2024/916.pdf) zkSNARK.
pub struct Polymath<E: Pairing> {
    _p: PhantomData<(E)>,
}

impl <E: Pairing> SNARK<E::ScalarField> for Polymath<E> {
    type ProvingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = PreparedVerifyingKey<E>;
    type Error = SynthesisError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        todo!();
        // let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        // let vk = pk.vk.clone();
        //
        // Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        todo!();
        // Self::create_random_proof_with_reduction(circuit, pk, rng)
    }

    fn process_vk(
        circuit_vk: &Self::VerifyingKey,
    ) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        todo!();
        // Ok(prepare_verifying_key(circuit_vk))
    }

    fn verify_with_processed_vk(
        circuit_pvk: &Self::ProcessedVerifyingKey,
        x: &[E::ScalarField],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Ok(Self::verify_proof(&circuit_pvk, proof, &x)?)
    }
}

impl<E: Pairing> CircuitSpecificSetupSNARK<E::ScalarField> for Polymath<E> {}
