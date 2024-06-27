use ark_ff::PrimeField;
use ark_std::{One, Zero};

use crate::pcs::UnivariatePCS;
use crate::{to_bytes, Polymath, PolymathError, Transcript, VerifyingKey};

use super::Proof;

/// `𝛼` is negative, we use it as an exponent of `y`: `y^𝛼 = (1/y)^(-𝛼)`
pub const MINUS_ALPHA: u64 = 3;

/// `𝛾` is negative, we use it as an exponent of `y`: `y^𝛾 = (1/y)^(-𝛾)`
pub const MINUS_GAMMA: u64 = 5;

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn compute_x1(
        t: &mut T,
        public_inputs: &[F],
        proof: &Proof<F, PCS>,
    ) -> Result<F, PolymathError> {
        t.append_message(b"public_inputs", &to_bytes!(&public_inputs)?);

        t.append_message(b"proof.a_g1", &to_bytes!(&proof.a_g1)?);
        t.append_message(b"proof.c_g1", &to_bytes!(&proof.c_g1)?);

        Ok(t.challenge(b"x1"))
    }

    /// y1 = x1^sigma
    pub(crate) fn compute_y1(x1: F, sigma: u64) -> F {
        x1.pow([sigma])
    }

    /// Compute `y^(exp)`, where exp is negative. `minus_exp` is thus positive.
    pub(crate) fn neg_power(y: F, minus_exp: u64) -> F {
        y.inverse().unwrap().pow([minus_exp])
    }

    pub(crate) fn compute_pi_at_x1(
        vk: &VerifyingKey<F, PCS>,
        public_inputs: &[F],
        x1: F,
        y1_gamma: F,
    ) -> F {
        let mut sum = F::zero();

        let mut lagrange_j_at_x1_numerator = (x1.pow([vk.n]) - F::one()) / &F::from(vk.n);
        let mut omega_exp_j = F::one();

        for j in 0..vk.m0 {
            let lagrange_k_j_at_x1 = lagrange_j_at_x1_numerator / (x1 - omega_exp_j);
            let to_add = Self::z_tilde_j(public_inputs, j) * lagrange_k_j_at_x1;
            lagrange_j_at_x1_numerator *= vk.omega;
            omega_exp_j *= vk.omega;
            sum += to_add;
        }

        sum * y1_gamma
    }

    pub(crate) fn compute_c_at_x1(y1_gamma: F, y1_alpha: F, a_at_x1: F, pi_at_x1: F) -> F {
        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1) / y1_alpha
    }

    fn z_tilde_j(public_inputs: &[F], j: u64) -> F {
        let two = &F::from(2);
        let j = j as usize;
        match j % 2 {
            0 => (public_inputs[j] + public_inputs[j + 1]) / two,
            1 => public_inputs[j] - public_inputs[j - 1] / two,
            _ => unreachable!(),
        }
    }
}
