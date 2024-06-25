use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::SerializationError;
use ark_std::{fmt::Debug, rand::Rng};

use crate::{ProvingKey, Transcript, VerifyingKey};

#[derive(thiserror::Error, Debug)]
pub enum PCSError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}

pub trait PCSVerifyingKey: Clone + Debug {}

pub trait PCSCommittingKey: Clone + Debug {}

pub trait UnivariatePCS<F: Field> {
    type Polynomial: Polynomial<F>;
    type Commitment: Clone + Eq + Debug;
    type EvalProof: Clone + Eq + Debug;
    type CommittingKey: PCSCommittingKey;
    type VerifyingKey: PCSVerifyingKey;
    type Transcript: Transcript<Challenge = F>;

    fn setup<R: Rng>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<(Self::CommittingKey, Self::VerifyingKey), PCSError>;

    fn commit(
        srs: &Self::CommittingKey,
        polynomial: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError>;

    fn prove_eval(
        srs: &Self::CommittingKey,
        polynomial: &Self::Polynomial,
        point: F,
        value: Option<F>,
    ) -> Result<(F, Self::EvalProof), PCSError>;

    fn batch_eval_single_point(
        srs: &Self::CommittingKey,
        polynomials: &[Self::Polynomial],
        point: F,
        values: &[Option<F>],
    ) -> Result<(Vec<F>, Self::EvalProof), PCSError>;

    fn verify(
        srs: &Self::VerifyingKey,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError>;

    fn batch_verify_single_point(
        srs: &Self::VerifyingKey,
        commitments: &[Self::Commitment],
        point: F,
        values: &[F],
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError>;
}

pub struct KZG<E: Pairing, P: Polynomial<E::ScalarField>, T: Transcript<Challenge = E::ScalarField>>
{
    _ept: PhantomData<(E, P, T)>,
}

impl<E: Pairing, P: Polynomial<E::ScalarField>, T: Transcript<Challenge = E::ScalarField>>
    UnivariatePCS<E::ScalarField> for KZG<E, P, T>
{
    type Polynomial = P;
    type Commitment = E::G1Affine;
    type EvalProof = E::G1Affine;
    type CommittingKey = ProvingKey<E>;
    type VerifyingKey = VerifyingKey<E>;
    type Transcript = T;

    fn setup<R: Rng>(
        max_degree: usize,
        rng: &mut R,
    ) -> Result<(Self::CommittingKey, Self::VerifyingKey), PCSError> {
        todo!()
    }

    fn commit(
        srs: &Self::CommittingKey,
        polynomial: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        todo!()
    }

    fn prove_eval(
        srs: &Self::CommittingKey,
        polynomial: &Self::Polynomial,
        point: E::ScalarField,
        value: Option<E::ScalarField>,
    ) -> Result<(E::ScalarField, Self::EvalProof), PCSError> {
        todo!()
    }

    fn batch_eval_single_point(
        srs: &Self::CommittingKey,
        polynomials: &[Self::Polynomial],
        point: E::ScalarField,
        values: &[Option<E::ScalarField>],
    ) -> Result<(Vec<E::ScalarField>, Self::EvalProof), PCSError> {
        todo!()
    }

    fn verify(
        srs: &Self::VerifyingKey,
        commitment: &Self::Commitment,
        point: E::ScalarField,
        value: E::ScalarField,
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError> {
        todo!()
    }

    fn batch_verify_single_point(
        srs: &Self::VerifyingKey,
        commitments: &[Self::Commitment],
        point: E::ScalarField,
        values: &[E::ScalarField],
        proof: &Self::EvalProof,
    ) -> Result<bool, PCSError> {
        todo!()
    }
}
