use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::Matrix;
use ark_std::iterable::Iterable;
use ark_std::{One, Zero};

use crate::pcs::UnivariatePCS;
use crate::{to_bytes, Polymath, PolymathError, Transcript, VerifyingKey};

pub const B_POLYMATH: &'static [u8; 8] = b"polymath";

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
        a_g1: &PCS::Commitment,
        c_g1: &PCS::Commitment,
    ) -> Result<F, PolymathError> {
        t.append_message(b"public_inputs", &to_bytes!(&public_inputs)?);

        t.append_message(b"proof.a_g1", &to_bytes!(a_g1)?);
        t.append_message(b"proof.c_g1", &to_bytes!(c_g1)?);

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

        let mut lagrange_i_at_x1_numerator = (x1.pow([vk.n]) - F::one()) / &F::from(vk.n);
        let mut omega_exp_i = F::one();

        let m0 = public_inputs.len();

        for i in 0..m0 * 2 {
            let lagrange_k_i_at_x1 = lagrange_i_at_x1_numerator / (x1 - omega_exp_i);
            let to_add = Self::z_tilde_i(public_inputs, i) * lagrange_k_i_at_x1;
            lagrange_i_at_x1_numerator *= vk.omega;
            omega_exp_i *= vk.omega;
            sum += to_add;
        }

        sum * y1_gamma
    }

    pub(crate) fn compute_c_at_x1(y1_gamma: F, y1_alpha: F, a_at_x1: F, pi_at_x1: F) -> F {
        ((a_at_x1 + y1_gamma) * a_at_x1 - pi_at_x1) / y1_alpha
    }

    fn z_tilde_i(public_inputs: &[F], i: usize) -> F {
        let m0 = public_inputs.len();
        let one = F::one();

        match i {
            0 => one + one,

            i if i < m0 => {
                let j = i;
                one + public_inputs[j]
            }

            i if i == m0 => F::zero(),

            i => {
                // i > m0
                let j = i - m0;
                one - public_inputs[j]
            }
        }
    }
}

pub(crate) fn m_at<F: Field>(m: &Matrix<F>, i: usize, j: usize) -> F {
    m[i].iter()
        .find(|(v, index)| *index == j)
        .unwrap_or(&(F::zero(), 0))
        .0
}
