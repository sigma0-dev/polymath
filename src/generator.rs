use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, Matrix, OptimizationGoal,
    SynthesisError, SynthesisMode,
};
use ark_std::rand::RngCore;

use crate::{Polymath, ProvingKey, Transcript};
use crate::pcs::UnivariatePCS;

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn generate_proving_key<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<ProvingKey<F, PCS>, SynthesisError> {
        type D<F> = Radix2EvaluationDomain<F>;

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

        let sap_matrices = SAPMatrices {
            r1cs_matrices: cs.to_matrices().unwrap(),
        };

        ///////////////////////////////////////////////////////////////////////////

        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let (n, m) = sap_matrices.size();
        let num_constraints = n;
        let domain = D::new(num_constraints).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        end_timer!(domain_time);
        ///////////////////////////////////////////////////////////////////////////

        let n = domain.size as i64;
        let sigma = n + 3;
        let d_min = -5 * n - 15;
        let d_max = 5 * n + 7;

        let x: F = domain.sample_element_outside_domain(rng);

        end_timer!(setup_time);

        todo!()
    }

    fn transform_matrices(matrices: ConstraintMatrices<F>, m0: usize) -> (Matrix<F>, Matrix<F>) {
        todo!()
    }
}

struct SAPMatrices<F: Field> {
    r1cs_matrices: ConstraintMatrices<F>,
}

impl<F: Field> SAPMatrices<F> {
    fn size(&self) -> (usize, usize) {
        let (m0, m, n) = self.m0_m_n();

        ((m0 + n) * 2, m0 * 2 + m + n)
    }

    fn u(&self, i: usize, j: usize) -> F {
        let matrices = &self.r1cs_matrices;

        let (m0, m, n) = self.m0_m_n();
        let (double_m0, double_m0_plus_n, double_m0_plus_double_n, m0_plus_m) =
            Self::inner_size_bounds(m0, m, n);

        let zero = F::zero();
        let one = F::one();
        let minus_one = -one;
        let two = one + one;

        match (i, j) {
            (0, 0) => two,                                       // (A₀+1)₀₀=2
            (i, 0) if i < m0 => one,                             // (A₀+1)ᵢ₀=1
            (i, j) if i < m0 && j == i => one,                   // (A₀+1)ᵢⱼ=1
            (i, 0) if i == m0 => zero,                           // (A₀-1)₀₀=0
            (i, 0) if i < double_m0 => one,                      // (A₀-1)ᵢ₀=1
            (i, j) if i < double_m0 && j == i - m0 => minus_one, // (A₀-1)ᵢⱼ=-1

            (i, _) if i < double_m0 => zero,
            (_, j) if j < m0 => zero,

            (i, j) if i < double_m0_plus_n && j < m0_plus_m => {
                let (i, j) = (i - double_m0, j - m0);
                m_at(&matrices.a, i, j) + m_at(&matrices.b, i, j)
            }
            (i, j) if i < double_m0_plus_double_n && j < m0_plus_m => {
                let (i, j) = (i - double_m0_plus_n, j - m0);
                m_at(&matrices.a, i, j) - m_at(&matrices.b, i, j)
            }
            (_, _) => zero,
        }
    }

    fn w(&self, i: usize, j: usize) -> F {
        let matrices = &self.r1cs_matrices;

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
                m_at(&matrices.c, i, j) * four
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
        let matrices = &self.r1cs_matrices;

        let m0 = matrices.num_instance_variables;
        let m = m0 + matrices.num_witness_variables; // full witness size (public + private)
        let n = matrices.num_constraints;
        (m0, m, n)
    }
}

fn m_at<F: Field>(m: &Matrix<F>, i: usize, j: usize) -> F {
    m[i].iter()
        .find(|(v, index)| *index == j)
        .unwrap_or(&(F::zero(), 0))
        .0
}
