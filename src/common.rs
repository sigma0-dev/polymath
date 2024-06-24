use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::{One, Zero};
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
        vk: &VerifyingKey<E>,
        public_inputs: &[E::ScalarField],
        x1: E::ScalarField,
        y1_gamma: E::ScalarField,
    ) -> E::ScalarField {
        let mut sum = E::ScalarField::zero();

        let mut lagrange_k_j_at_x1_numerator =
            (x1.pow(&[vk.m0]) - E::ScalarField::one()) / &E::ScalarField::from(vk.m0);
        let mut nu_exp_j = E::ScalarField::one();

        for j in 0..vk.m0 {
            let lagrange_k_j_at_x1 = lagrange_k_j_at_x1_numerator / (x1 - nu_exp_j);
            let to_add = Self::z_tilde_j(public_inputs, j) * lagrange_k_j_at_x1;
            lagrange_k_j_at_x1_numerator *= vk.nu;
            nu_exp_j *= vk.nu;
            sum += to_add;
        }

        sum * y1_gamma
    }

    pub(crate) fn compute_c_at_x1(
        vk: &VerifyingKey<E>,
        x1: E::ScalarField,
        y1_gamma: E::ScalarField,
        y1_alpha: E::ScalarField,
        a_at_x1: E::ScalarField,
        pi_at_x1: E::ScalarField,
    ) -> E::ScalarField {
        let z_h_no_k_at_x1 = Self::z_h_wo_k(vk, x1);

        let m0 = E::ScalarField::from(vk.m0);
        let n = E::ScalarField::from(vk.n);

        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1 * z_h_no_k_at_x1 * m0 / n) / y1_alpha
    }

    fn z_tilde_j(public_inputs: &[E::ScalarField], j: u64) -> E::ScalarField {
        let two = &E::ScalarField::from(2);
        let j = j as usize;
        match j % 2 {
            0 => (public_inputs[j] + public_inputs[j + 1]) / two,
            1 => public_inputs[j] - public_inputs[j - 1] / two,
            _ => unreachable!(),
        }
    }

    fn z_h_wo_k(vk: &VerifyingKey<E>, x1: E::ScalarField) -> E::ScalarField {
        let one = E::ScalarField::one();
        (x1.pow(&[vk.n]) - one) / (x1.pow(&[vk.m0]) - one)
    }
}
