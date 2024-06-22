use ark_ec::pairing::Pairing;
use ark_ff::Field;
use flexible_transcript::Transcript;

use crate::pcs::UnivariatePCS;
use crate::{to_bytes, Polymath, PolymathError, VerifyingKey};

use super::Proof;

/// `𝛼` is negative, we use it as an exponent of `y`: `y^𝛼 = (1/y)^(-𝛼)`
pub const MINUS_ALPHA: u64 = 3;

/// `𝛾` is negative, we use it as an exponent of `y`: `y^𝛾 = (1/y)^(-𝛾)`
pub const MINUS_GAMMA: u64 = 5;

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
    pub(crate) fn compute_y1(x1: E::ScalarField, sigma: u64) -> E::ScalarField {
        x1.pow(&[sigma])
    }

    /// Compute `y^(exp)`, where exp is negative. `minus_exp` is thus positive.
    pub(crate) fn neg_power(y: E::ScalarField, minus_exp: u64) -> E::ScalarField {
        y.inverse().unwrap().pow(&[minus_exp])
    }

    pub(crate) fn compute_pi_at_x1(
        public_inputs: &[E::ScalarField],
        x1: E::ScalarField,
        y1_gamma: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }

    pub(crate) fn compute_c_at_x1(
        x1: E::ScalarField,
        y1_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
    ) -> E::ScalarField {
        todo!()
    }
}
