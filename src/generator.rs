use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal, SynthesisError,
    SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;

use crate::pcs::UnivariatePCS;
use crate::{Polymath, PolymathError, ProvingKey, Transcript, VerifyingKey};

type D<F> = Radix2EvaluationDomain<F>;

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn generate_proving_key<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<ProvingKey<F, PCS>, PolymathError> {
        let setup_time = start_timer!(|| "Polymath::Generator");
        ///////////////////////////////////////////////////////////////////////////

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        ///////////////////////////////////////////////////////////////////////////

        let r1cs_matrices = cs.to_matrices().unwrap();
        let sap_matrices = SAPMatrices {
            num_instance_variables: r1cs_matrices.num_instance_variables,
            num_witness_variables: r1cs_matrices.num_witness_variables,
            num_constraints: r1cs_matrices.num_constraints,
            a: r1cs_matrices.a,
            b: r1cs_matrices.b,
            c: r1cs_matrices.c,
        };

        ///////////////////////////////////////////////////////////////////////////

        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let (n, m) = sap_matrices.size();
        let num_constraints = n; // unaligned to powers of 2
        let domain = D::new(num_constraints).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        end_timer!(domain_time);
        ///////////////////////////////////////////////////////////////////////////

        let u_polynomials = Self::polynomials(&domain, m, |i, j| sap_matrices.u(i, j));
        let w_polynomials = Self::polynomials(&domain, m, |i, j| sap_matrices.w(i, j));

        let n = domain.size; // a power of 2
        let sigma = n + 3;
        // let d_min = -5 * n - 15;
        // let d_max = 5 * n + 7;

        let x: F = domain.sample_element_outside_domain(rng);

        let (pcs_ck, pcs_vk) = PCS::setup(domain.size(), rng)?;

        end_timer!(setup_time);

        Ok(ProvingKey {
            pcs_ck,
            vk: VerifyingKey {
                pcs_vk,
                n,
                m0: cs.num_instance_variables() as u64,
                sigma,
                omega: domain.group_gen(),
            },
            domain,
            sap_matrices,
            u_polynomials,
            w_polynomials,
            x_powers_g1: vec![],
            x_powers_y_alpha_g1: vec![],
            uw_j_lcs_by_y_alpha_g1: vec![],
        })
    }

    fn polynomials<D: EvaluationDomain<F>, M: Fn(usize, usize) -> F>(
        domain: &D,
        m: usize,
        m_ij: M,
    ) -> Vec<Vec<F>> {
        (0..m)
            .map(|j| Self::poly_coeff_vec(domain, j, &m_ij))
            .collect()
    }

    fn poly_coeff_vec<D: EvaluationDomain<F>, M: Fn(usize, usize) -> F>(
        domain: &D,
        j: usize,
        m: &M,
    ) -> Vec<F> {
        let mut poly_def = (0..domain.size()).map(|i| m(i as usize, j)).collect(); // poly evals
        domain.ifft_in_place(&mut poly_def); // make coeffs from evals
        poly_def
    }
}

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct SAPMatrices<F: Field> {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,

    pub a: Vec<Vec<(F, usize)>>,
    pub b: Vec<Vec<(F, usize)>>,
    pub c: Vec<Vec<(F, usize)>>,
}

impl<F: Field> SAPMatrices<F> {
    fn size(&self) -> (usize, usize) {
        let (m0, m, n) = self.m0_m_n();

        ((m0 + n) * 2, m0 * 2 + m + n)
    }

    fn u(&self, i: usize, j: usize) -> F {
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

    fn w(&self, i: usize, j: usize) -> F {
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
            (i, j) if i < double_m0_plus_n => zero,

            (i, j) if i < double_m0_plus_double_n && j == i - n + m => one,

            (_, _) => zero,
        }
    }

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

    fn m0_m_n(&self) -> (usize, usize, usize) {
        let m0 = self.num_instance_variables;
        let m = m0 + self.num_witness_variables; // full witness size (public + private)
        let n = self.num_constraints;
        (m0, m, n)
    }
}

fn m_at<F: Field>(m: &Matrix<F>, i: usize, j: usize) -> F {
    m[i].iter()
        .find(|(v, index)| *index == j)
        .unwrap_or(&(F::zero(), 0))
        .0
}
