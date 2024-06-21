use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::SerializationError;
use ark_std::rand::Rng;
use flexible_transcript::Transcript;

#[derive(thiserror::Error, Debug)]
pub enum PCSError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}

pub trait UnivariatePCS<F: Field> {
    type Polynomial: Polynomial<F>;
    type Commitment: Clone + Eq + std::fmt::Debug;
    type EvalProof: Clone + Eq + std::fmt::Debug;
    type SRS: Clone + Eq + std::fmt::Debug;
    type Transcript: Transcript<Challenge = F>;

    fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<Self::SRS, PCSError>;

    fn commit(srs: &Self::SRS, polynomial: &Self::Polynomial)
        -> Result<Self::Commitment, PCSError>;

    fn prove_eval(
        srs: &Self::SRS,
        polynomial: &Self::Polynomial,
        point: F,
        value: Option<F>,
    ) -> Result<(F, Self::EvalProof), PCSError>;

    fn batch_eval_single_point(
        srs: &Self::SRS,
        polynomials: &[Self::Polynomial],
        point: F,
        values: &[Option<F>],
        transcript: &Self::Transcript,
    ) -> Result<(Vec<F>, Self::EvalProof), PCSError>;

    fn verify(
        srs: &Self::SRS,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError>;
}
