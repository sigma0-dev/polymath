use ark_ec::{AffineRepr, pairing::Pairing};
use flexible_transcript::Transcript;

use crate::{Polymath, PolymathError, to_bytes};

use super::{PreparedVerifyingKey, Proof, VerifyingKey};

/// Prepare the verifying key `vk` for use in proof verification.
pub fn prepare_verifying_key<E: Pairing>(vk: &VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    PreparedVerifyingKey { vk: vk.clone() }
}

impl<E: Pairing, T> Polymath<E, T>
where
    T: Transcript<Challenge = E::ScalarField>,
{
    /// Verify a Polymath proof `proof` against the prepared verification key `pvk`,
    /// with respect to the instance `public_inputs`.
    pub fn verify_proof(
        pvk: &PreparedVerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> Result<bool, PolymathError> {
        let mut t = T::new(b"polymath");

        // compute challenge x1
        let x1: E::ScalarField = Self::compute_x1(&mut t, public_inputs, proof)?;

        todo!()
    }

    fn compute_x1(
        t: &mut T,
        public_inputs: &[E::ScalarField],
        proof: &Proof<E>,
    ) -> Result<E::ScalarField, PolymathError> {
        t.append_message(b"public_inputs", &to_bytes!(&public_inputs)?);

        t.append_message(b"proof.a_g1", &to_bytes!(&proof.a_g1)?);
        t.append_message(b"proof.c_g1", &to_bytes!(&proof.c_g1)?);

        Ok(t.challenge(b"x1"))
    }
}
