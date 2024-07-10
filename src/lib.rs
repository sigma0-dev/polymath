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

use ark_crypto_primitives::snark::*;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_serialize::SerializationError;
use ark_std::marker::PhantomData;
use ark_std::{clone::Clone, fmt::Debug, rand::RngCore, result::Result};

pub use self::data_structures::*;
pub use self::transcript::*;

/// Data structures used by the prover, verifier, and generator.
pub mod data_structures;

/// Generate public parameters for the Polymath zkSNARK construction.
pub mod generator;

/// Create proofs for the Polymath zkSNARK construction.
pub mod prover;

/// Verify proofs for the Polymath zkSNARK construction.
pub mod verifier;

mod common;
mod r#macro;
#[cfg(test)]
mod test;
pub mod transcript;

/// The [Polymath](https://eprint.iacr.org/2024/916.pdf) zkSNARK.
pub struct Polymath<E, T>
where
    E: Pairing,
    T: Transcript<Challenge = E::ScalarField>,
{
    _p: PhantomData<(E, T)>,
}

impl<F: PrimeField, E, T> SNARK<F> for Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
    type ProvingKey = ProvingKey<F, E>;
    type VerifyingKey = VerifyingKey<F, E>;
    type Proof = Proof<E>;
    type ProcessedVerifyingKey = VerifyingKey<F, E>;
    type Error = PolymathError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        let pk = Self::generate_proving_key(circuit, rng)?;
        let vk = pk.vk.clone();
        Ok((pk, vk))
    }

    fn prove<C: ConstraintSynthesizer<F>, R: RngCore>(
        pk: &Self::ProvingKey,
        circuit: C,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error> {
        Self::create_proof(circuit, pk, rng)
    }

    fn process_vk(vk: &Self::VerifyingKey) -> Result<Self::ProcessedVerifyingKey, Self::Error> {
        Ok(vk.clone())
    }

    fn verify_with_processed_vk(
        vk: &Self::ProcessedVerifyingKey,
        x: &[F],
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        Self::verify_proof(vk, proof, x)
    }
}

impl<F: PrimeField, E, T> CircuitSpecificSetupSNARK<F> for Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
}

#[derive(thiserror::Error, Debug)]
pub enum PolymathError {
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    // #[error(transparent)]
    // PCSError(#[from] PCSError),
}
