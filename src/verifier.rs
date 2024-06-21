use ark_ec::pairing::Pairing;
use flexible_transcript::Transcript;

use crate::pcs::UnivariatePCS;
use crate::{to_bytes, Polymath, PolymathError, VerifyingKey};

use super::Proof;

impl<E: Pairing, T, PCS> Polymath<E, T, PCS>
where
    T: Transcript<Challenge = E::ScalarField>,
    PCS: UnivariatePCS<
        E::ScalarField,
        Commitment = E::G1Affine,
        EvalProof = E::G1Affine,
        Transcript = T,
        SrsV = VerifyingKey<E>,
    >,
{
    /// Verify a Polymath proof `proof` against the verification key `vk`,
    /// with respect to the instance `public_inputs`.
    pub(crate) fn verify_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[E::ScalarField],
    ) -> Result<bool, PolymathError> {
        let mut t = T::new(b"polymath");

        // compute challenge x1
        let x1: E::ScalarField = Self::compute_x1(&mut t, public_inputs, proof)?;
        // compute y1=x1^sigma
        let y1: E::ScalarField = Self::compute_y1(x1);

        let pi_at_x1 = Self::compute_pi_at_x1(proof.a_at_x1, public_inputs, x1, y1);

        // compute c_at_x1
        let c_at_x1 = Self::compute_c_at_x1(x1, y1, proof.a_at_x1, pi_at_x1);

        PCS::batch_verify_single_point(
            vk,
            &[proof.a_g1, proof.c_g1],
            x1,
            &[proof.a_at_x1, c_at_x1],
            &proof.d_g1,
        )
        .map_err(|e| e.into())
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

    /// y1 = x1^sigma
    fn compute_y1(x1: E::ScalarField) -> E::ScalarField {
        todo!()
    }

    fn compute_pi_at_x1(
        a_at_x1: E::ScalarField,
        public_inputs: &[E::ScalarField],
        x1: E::ScalarField,
        y1: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }

    fn compute_c_at_x1(
        x1: E::ScalarField,
        y1: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }
}
