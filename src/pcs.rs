use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::SerializationError;
use ark_std::{fmt::Debug, rand::Rng};
use flexible_transcript::Transcript;

#[derive(thiserror::Error, Debug)]
pub enum PCSError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}

pub trait UnivariatePCS<F: Field> {
    type Polynomial: Polynomial<F>;
    type Commitment: Clone + Eq + Debug;
    type EvalProof: Clone + Eq + Debug;
    type SrsP: Clone + Eq + Debug;
    type SrsV: Clone + Eq + Debug;
    type Transcript: Transcript<Challenge = F>;

    fn setup<R: Rng>(max_degree: usize, rng: &mut R) -> Result<(Self::SrsP, Self::SrsV), PCSError>;

    fn commit(
        srs: &Self::SrsP,
        polynomial: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError>;

    fn prove_eval(
        srs: &Self::SrsP,
        polynomial: &Self::Polynomial,
        point: F,
        value: Option<F>,
    ) -> Result<(F, Self::EvalProof), PCSError>;

    fn batch_eval_single_point(
        srs: &Self::SrsP,
        polynomials: &[Self::Polynomial],
        point: F,
        values: &[Option<F>],
    ) -> Result<(Vec<F>, Self::EvalProof), PCSError>;

    fn verify(
        srs: &Self::SrsV,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError>;

    fn batch_verify_single_point(
        srs: &Self::SrsV,
        commitments: &[Self::Commitment],
        point: F,
        values: &[F],
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError>;
}
