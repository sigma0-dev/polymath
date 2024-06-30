use ark_ff::PrimeField;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_std::iterable::Iterable;
use ark_std::rand::RngCore;

use crate::common::m_at;
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
        // Produce a witness, do not generate matrices
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let prover = cs.borrow().unwrap();
        let proof = Self::create_proof_with_assignment(
            pk,
            &prover.instance_assignment,
            &prover.witness_assignment,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    fn create_proof_with_assignment(
        pk: &ProvingKey<F, PCS>,
        instance_assignment: &[F],
        witness_assignment: &[F],
    ) -> Result<Proof<F, PCS>, PolymathError>
    where
        PCS: UnivariatePCS<F, Transcript = T>,
        T: Transcript<Challenge = F>,
    {
        let z = &[
            instance_assignment,
            instance_assignment,
            witness_assignment,
            &Self::compute_y_vec(pk, instance_assignment, witness_assignment),
        ];
        todo!()
    }

    fn compute_y_vec(pk: &ProvingKey<F, PCS>, x: &[F], w: &[F]) -> Vec<F> {
        let zero = F::zero();
        let one = F::one();
        let y_m0: Vec<F> = (1..pk.sap_matrices.num_witness_variables)
            .map(|j| one - x[j])
            .collect();

        let (a, b) = (&pk.sap_matrices.a, &pk.sap_matrices.b);

        let y_n: Vec<F> = (0..pk.sap_matrices.num_r1cs_constraints)
            .map(|i| {
                let num_r1cs_columns =
                    pk.sap_matrices.num_instance_variables + pk.sap_matrices.num_witness_variables;
                (0..num_r1cs_columns)
                    .map(|j| (m_at(a, i, j) - m_at(b, i, j)) * Self::combined_v_at(&[x, w], j))
                    .fold(zero, |x, y| x + y)
            })
            .collect();
        vec![vec![F::zero()], y_m0, y_n].concat()
    }

    fn combined_v_at(vectors: &[&[F]], j: usize) -> F {
        let mut j = j;
        for &v in vectors {
            if j < v.len() {
                return v[j];
            }
            j -= v.len();
        }
        unreachable!()
    }
}
