use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError};
use ark_std::rand::RngCore;

use crate::pcs::UnivariatePCS;
use crate::{Polymath, ProvingKey, Transcript};

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn generate_proving_key<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<ProvingKey<F, PCS>, SynthesisError> {
        todo!()
    }
}
