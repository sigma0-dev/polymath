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
use ark_std::{clone::Clone, fmt::Debug, rand::RngCore, result::Result};
use ark_std::marker::PhantomData;

use crate::pcs::{PCSError, UnivariatePCS};

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
pub mod pcs;
#[cfg(test)]
mod test;
pub mod transcript;

/// The [Polymath](https://eprint.iacr.org/2024/916.pdf) zkSNARK.
pub struct Polymath<F: PrimeField, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    _p: PhantomData<(F, T, PCS)>,
}

impl<F: PrimeField, T, PCS> SNARK<F> for Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    type ProvingKey = ProvingKey<F, PCS>;
    type VerifyingKey = VerifyingKey<F, PCS>;
    type Proof = Proof<F, PCS>;
    type ProcessedVerifyingKey = VerifyingKey<F, PCS>;
    type Error = PolymathError;

    fn circuit_specific_setup<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), Self::Error> {
        todo!();
        // let pk = Self::generate_random_parameters_with_reduction(circuit, rng)?;
        // let vk = pk.vk.clone();
        //
        // Ok((pk, vk))
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

impl<F: PrimeField, T, PCS> CircuitSpecificSetupSNARK<F> for Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
}

#[derive(thiserror::Error, Debug)]
pub enum PolymathError {
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
    #[error(transparent)]
    PCSError(#[from] PCSError),
}
