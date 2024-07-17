use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_relations::r1cs::Matrix;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{to_bytes, Polymath, PolymathError, Transcript, VerifyingKey};

pub const B_POLYMATH: &[u8; 8] = b"polymath";

/// `𝛼` is negative, we use it as an exponent of `y`: `y^𝛼 = (1/y)^(-𝛼)`
pub const MINUS_ALPHA: u64 = 3;

/// `𝛾` is negative, we use it as an exponent of `y`: `y^𝛾 = (1/y)^(-𝛾)`
pub const MINUS_GAMMA: u64 = 5;

impl<F: PrimeField, E, T> Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
    pub(crate) fn compute_x1(
        t: &mut T,
        public_inputs: &[F],
        commitments: &[E::G1Affine],
    ) -> Result<F, PolymathError> {
        t.append_message(b"public_inputs", &to_bytes!(&public_inputs)?);
        t.append_message(b"commitments", &to_bytes!(commitments)?);

        Ok(t.challenge(b"x1"))
    }

    pub(crate) fn compute_x2(t: &mut T, x1: &F, values: &[F]) -> Result<F, PolymathError> {
        t.append_message(b"x1", &to_bytes!(x1)?);
        t.append_message(b"values", &to_bytes!(values)?);

        Ok(t.challenge(b"x2"))
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
        vk: &VerifyingKey<E>,
        public_inputs: &[F],
        x1: F,
        y1_gamma: F,
    ) -> F {
        let mut sum = F::zero();

        let mut lagrange_i_at_x1_numerator = (x1.pow([vk.n]) - F::one()) / &F::from(vk.n);
        let mut omega_exp_i = F::one();

        let m0 = public_inputs.len();

        for i in 0..m0 * 2 {
            let lagrange_i_at_x1 = lagrange_i_at_x1_numerator / (x1 - omega_exp_i);
            let to_add = Self::z_tilde_i(public_inputs, i) * lagrange_i_at_x1;
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
        .find(|(_, index)| *index == j)
        .unwrap_or(&(F::zero(), 0))
        .0
}

/// SAP (square arithmetic program) matrix representation of underlying R1CS.
/// SAP: `Uz ∘ Uz = Wz`
/// R1CS: `Az ∘ Bz = Cz`
/// We are constructing the views into SAP `U` and `W` matrices from R1CS
/// preserving the constraints encoded in the underlying R1CS.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct SAPMatrices<F: Field> {
    /// Number of public input (a.k.a. instance) variables in the underlying R1CS, including the leading `1`.
    pub num_instance_variables: usize,
    /// Number of private (a.k.a. witness) variables in the underlying R1CS.
    pub num_r1cs_witness_variables: usize,
    /// Number of constraints in the underlying R1CS.
    pub num_r1cs_constraints: usize,

    /// R1CS `A` matrix.
    pub a: Vec<Vec<(F, usize)>>,
    /// R1CS `B` matrix.
    pub b: Vec<Vec<(F, usize)>>,
    /// R1CS `C` matrix.
    pub c: Vec<Vec<(F, usize)>>,
}

impl<F: Field> SAPMatrices<F> {
    /// Number of rows and columns in SAP matrices.
    pub fn size(&self) -> (usize, usize) {
        let (m0, m, n) = self.m0_m_n();

        ((m0 + n) * 2, m0 * 2 + m + n)
    }

    /// Get `Uᵢⱼ` element of the SAP `U` matrix.
    pub fn u(&self, i: usize, j: usize) -> F {
        let (m0, m, n) = self.m0_m_n();
        let (double_m0, double_m0_plus_n, double_m0_plus_double_n, m0_plus_m) =
            Self::inner_size_bounds(m0, m, n);

        let zero = F::zero();
        let one = F::one();
        let minus_one = -one;
        let two = one + one;

        match (i, j) {
            (0, 0) => two,                     // (A₀+1)₀₀=2
            (i, 0) if i < m0 => one,           // (A₀+1)ᵢ₀=1
            (i, j) if i < m0 && j == i => one, // (A₀+1)ᵢⱼ=1

            (i, _) if i < m0 => zero,

            (i, 0) if i == m0 => zero,      // (A₀-1)₀₀=0
            (i, 0) if i < double_m0 => one, // (A₀-1)ᵢ₀=1
            (i, j) if i < double_m0 && j == i - m0 => minus_one, // (A₀-1)ᵢⱼ=-1

            (i, _) if i < double_m0 => zero,
            (_, j) if j < m0 => zero,

            (i, j) if i < double_m0_plus_n && j < m0_plus_m => {
                let (i, j) = (i - double_m0, j - m0);
                m_at(&self.a, i, j) + m_at(&self.b, i, j)
            }
            (i, j) if i < double_m0_plus_double_n && j < m0_plus_m => {
                let (i, j) = (i - double_m0_plus_n, j - m0);
                m_at(&self.a, i, j) - m_at(&self.b, i, j)
            }
            (_, _) => zero,
        }
    }

    /// Get `Wᵢⱼ` element of the SAP `W` matrix.
    pub fn w(&self, i: usize, j: usize) -> F {
        let (m0, m, n) = self.m0_m_n();
        let (double_m0, double_m0_plus_n, double_m0_plus_double_n, m0_plus_m) =
            Self::inner_size_bounds(m0, m, n);

        let zero = F::zero();
        let one = F::one();
        let two = one + one;
        let four = two + two;

        match (i, j) {
            (i, j) if i < m0 && j == i + m0 => four,
            (i, j) if i < m0 && j == i + m0_plus_m => one,
            (i, _) if i < m0 => zero,

            (i, j) if i < double_m0 && j == i + m => one,

            (i, _) if i < double_m0 => zero,
            (_, j) if j < m0 => zero,

            (i, j) if i < double_m0_plus_n && j < m0_plus_m => {
                let (i, j) = (i - double_m0, j - m0);
                m_at(&self.c, i, j) * four
            }

            (i, j) if i < double_m0_plus_n && j == i + m => one,
            (i, _) if i < double_m0_plus_n => zero,

            (i, j) if i < double_m0_plus_double_n && j == i - n + m => one,

            (_, _) => zero,
        }
    }

    #[inline]
    fn inner_size_bounds(m0: usize, m: usize, n: usize) -> (usize, usize, usize, usize) {
        let double_m0 = m0 + m0;
        let double_m0_plus_n = double_m0 + n;
        let double_m0_plus_double_n = double_m0_plus_n + n;
        let m0_plus_m = m0 + m;
        (
            double_m0,
            double_m0_plus_n,
            double_m0_plus_double_n,
            m0_plus_m,
        )
    }

    #[inline]
    fn m0_m_n(&self) -> (usize, usize, usize) {
        let m0 = self.num_instance_variables;
        let m = m0 + self.num_r1cs_witness_variables; // full R1CS witness size (public + private)
        let n = self.num_r1cs_constraints;
        (m0, m, n)
    }
}
