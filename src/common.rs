use ark_ec::pairing::Pairing;
use ark_ff::Field;
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
    pub(crate) fn compute_x1(
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
    pub(crate) fn compute_y1(sigma: u64, x1: E::ScalarField) -> E::ScalarField {
        x1.pow(&[sigma])
    }

    pub(crate) fn compute_pi_at_x1(
        a_at_x1: E::ScalarField,
        public_inputs: &[E::ScalarField],
        x1: E::ScalarField,
        y1: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }

    pub(crate) fn compute_c_at_x1(
        x1: E::ScalarField,
        y1: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }
}
