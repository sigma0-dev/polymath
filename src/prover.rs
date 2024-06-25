use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_std::rand::RngCore;

use crate::pcs::UnivariatePCS;
use crate::{Polymath, PolymathError, Proof, ProvingKey, Transcript};

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn create_proof<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<F, PCS>,
        rng: &mut R,
    ) -> Result<Proof<F, PCS>, PolymathError> {
        let prover_time = start_timer!(|| "Polymath::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        end_timer!(prover_time);
        todo!()

        // Ok(proof)
    }
}
