use ark_ec::pairing::Pairing;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_std::rand::RngCore;
use flexible_transcript::Transcript;

use crate::{Polymath, PolymathError, Proof, ProvingKey, VerifyingKey};
use crate::pcs::UnivariatePCS;

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
    pub(crate) fn create_proof<C: ConstraintSynthesizer<E::ScalarField>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut R,
    ) -> Result<Proof<E>, PolymathError> {
        todo!()
    }
}
