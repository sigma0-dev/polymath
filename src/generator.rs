use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
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

        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let domain_size = cs.num_constraints();
        let domain = D::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

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
}
