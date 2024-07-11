use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM;
use ark_ff::PrimeField;
use ark_std::One;

use crate::common::{B_POLYMATH, MINUS_ALPHA, MINUS_GAMMA};
use crate::{Polymath, PolymathError, Transcript, VerifyingKey};

use super::Proof;

impl<F: PrimeField, E, T> Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
    /// Verify a Polymath proof `proof` against the verification key `vk`,
    /// with respect to the instance `public_inputs`.
    pub(crate) fn verify_proof(
        vk: &VerifyingKey<E>,
        proof: &Proof<E>,
        public_inputs: &[F],
    ) -> Result<bool, PolymathError> {
        let mut t = T::new(B_POLYMATH);

        let public_inputs = &[&[F::one()], public_inputs].concat();

        dbg!(public_inputs);

        // compute challenge x1
        dbg!(&proof.a_g1);
        dbg!(&proof.c_g1);

        let x1: F = Self::compute_x1(&mut t, public_inputs, &[proof.a_g1, proof.c_g1])?;

        dbg!(x1);

        // compute y1=x1^sigma
        let y1: F = Self::compute_y1(x1, vk.sigma);

        dbg!(y1);

        let y1_gamma = Self::neg_power(y1, MINUS_GAMMA);
        let pi_at_x1 = Self::compute_pi_at_x1(vk, public_inputs, x1, y1_gamma);

        let y1_alpha = Self::neg_power(y1, MINUS_ALPHA);

        // compute c_at_x1
        let c_at_x1 = Self::compute_c_at_x1(y1_gamma, y1_alpha, proof.a_at_x1, pi_at_x1);

        dbg!(c_at_x1);

        let x2 = Self::compute_x2(&mut t, &x1, &[proof.a_at_x1, c_at_x1])?;

        dbg!(x2);

        let commitments_minus_evals_in_g1 = E::G1::msm_unchecked(
            &[proof.a_g1, proof.c_g1, vk.vk.one_g1],
            &[F::one(), x2, -(proof.a_at_x1 + x2 * c_at_x1)],
        );
        let x_minus_x1_in_g2 = E::G2::msm_unchecked(&[vk.vk.x_g2, vk.vk.one_g2], &[F::one(), -x1]);

        let pairing_output = E::multi_pairing(
            [
                <E::G1 as Into<E::G1Prepared>>::into(commitments_minus_evals_in_g1),
                <E::G1 as Into<E::G1Prepared>>::into(proof.d_g1 * (-F::one())),
            ],
            [
                <E::G2 as Into<E::G2Prepared>>::into(vk.vk.z_g2.into()),
                <E::G2 as Into<E::G2Prepared>>::into(x_minus_x1_in_g2),
            ],
        );

        dbg!(pairing_output.0);

        Ok(pairing_output.0.is_one())
    }
}
