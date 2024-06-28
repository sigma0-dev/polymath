use ark_ff::PrimeField;
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

        // TODO transform R1CS matrices A, B, C into SAP U and W

        let m0 = cs.num_instance_variables();

        let matrices = cs.to_matrices().unwrap();

        let (u, w): (Matrix<F>, Matrix<F>) = Self::transform_matrices(matrices, m0);
        // let (i, j) = (0, 10);
        // let u_ij = u[i]
        //     .iter()
        //     .find(|(v, index)| *index == j)
        //     .unwrap_or(&(F::zero(), 0))
        //     .0;

        ///////////////////////////////////////////////////////////////////////////

        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let num_constraints = u.len();
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
