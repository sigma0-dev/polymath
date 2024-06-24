use ark_ec::pairing::Pairing;
use flexible_transcript::Transcript;

use crate::common::{MINUS_ALPHA, MINUS_GAMMA};
use crate::pcs::UnivariatePCS;
use crate::{Polymath, PolymathError, VerifyingKey};

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
        let y1: E::ScalarField = Self::compute_y1(x1, vk.sigma);

        let y1_gamma = Self::neg_power(y1, MINUS_GAMMA);
        let pi_at_x1 = Self::compute_pi_at_x1(vk, public_inputs, x1, y1_gamma);

        let y1_alpha = Self::neg_power(y1, MINUS_ALPHA);

        // compute c_at_x1
        let c_at_x1 = Self::compute_c_at_x1(vk, x1, y1_gamma, y1_alpha, proof.a_at_x1, pi_at_x1);

        PCS::batch_verify_single_point(
            vk,
            &[proof.a_g1, proof.c_g1],
            x1,
            &[proof.a_at_x1, c_at_x1],
            &proof.d_g1,
        )
        .map_err(|e| e.into())
    }
}
