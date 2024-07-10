use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::iterable::Iterable;
use ark_std::{clone::Clone, fmt::Debug, rand::Rng};

use crate::{KZGVerifyingKey, Transcript};

#[derive(thiserror::Error, Debug)]
pub enum PCSError {
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}

pub trait HasPCSCommittingKey<F: Field, PCS: UnivariatePCS<F>> {
    fn get_pcs_ck(&self) -> &PCS::CommittingKey;
}

pub trait HasPCSVerifyingKey<F: Field, PCS: UnivariatePCS<F>> {
    fn get_pcs_vk(&self) -> &PCS::VerifyingKey;
}

// `: Clone` bound is needed by Polymath to implement SNARK associated types (that are all `: Clone`)
pub trait UnivariatePCS<F: Field>: Clone {
    type ToBeCommitted;
    type Commitment: Clone
        + Copy
        + Eq
        + PrimeGroup<ScalarField = F>
        + ScalarMul
        + VariableBaseMSM
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize;
    type CommittingKey: Clone + Copy + Debug + CanonicalSerialize + CanonicalDeserialize;
    type VerifyingKey: Clone + Copy + Debug + CanonicalSerialize + CanonicalDeserialize;
    type Transcript: Transcript<Challenge = F>;

    fn commit(
        srs: &Self::CommittingKey,
        seq: &Self::ToBeCommitted,
    ) -> Result<Self::Commitment, PCSError>;

    fn prove_eval(
        srs: &Self::CommittingKey,
        polynomial: &Self::ToBeCommitted,
        point: F,
        value: Option<F>,
    ) -> Result<(F, Self::Commitment), PCSError>;

    fn batch_eval_single_point(
        srs: &Self::CommittingKey,
        polynomials: &[Self::ToBeCommitted],
        point: F,
        values: &[Option<F>],
    ) -> Result<(Vec<F>, Self::Commitment), PCSError>;

    fn verify(
        srs: &Self::VerifyingKey,
        commitment: &Self::Commitment,
        point: F,
        value: F,
        proof: &Self::Commitment,
    ) -> Result<bool, PCSError>;

    fn batch_verify_single_point(
        t: &mut Self::Transcript,
        srs: &Self::VerifyingKey,
        commitments: &[Self::Commitment],
        point: F,
        values: &[F],
        proof: &Self::Commitment,
    ) -> Result<bool, PCSError>;
}

#[derive(Clone)]
pub struct KZG<E: Pairing, T: Transcript<Challenge = E::ScalarField>> {
    _ept: PhantomData<(E, T)>,
}

#[derive(Clone, Copy, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGCommittingKey<E: Pairing> {
    _e: PhantomData<E>,
}

impl<E: Pairing, T: Transcript<Challenge = E::ScalarField>> UnivariatePCS<E::ScalarField>
    for KZG<E, T>
{
    type ToBeCommitted = Vec<E::ScalarField>;
    type Commitment = E::G1;
    type CommittingKey = KZGCommittingKey<E>;
    type VerifyingKey = KZGVerifyingKey<E>;
    type Transcript = T;

    fn commit(
        srs: &Self::CommittingKey,
        polynomial: &Self::ToBeCommitted,
    ) -> Result<Self::Commitment, PCSError> {
        todo!()
    }

    fn prove_eval(
        srs: &Self::CommittingKey,
        polynomial: &Self::ToBeCommitted,
        point: E::ScalarField,
        value: Option<E::ScalarField>,
    ) -> Result<(E::ScalarField, Self::Commitment), PCSError> {
        todo!()
    }

    fn batch_eval_single_point(
        srs: &Self::CommittingKey,
        polynomials: &[Self::ToBeCommitted],
        point: E::ScalarField,
        values: &[Option<E::ScalarField>],
    ) -> Result<(Vec<E::ScalarField>, Self::Commitment), PCSError> {
        todo!()
    }

    fn verify(
        srs: &Self::VerifyingKey,
        commitment: &Self::Commitment,
        point: E::ScalarField,
        value: E::ScalarField,
        proof: &Self::Commitment,
    ) -> Result<bool, PCSError> {
        todo!()
    }

    fn batch_verify_single_point(
        t: &mut T,
        vk: &Self::VerifyingKey,
        commitments: &[Self::Commitment],
        point: E::ScalarField,
        values: &[E::ScalarField],
        proof: &Self::Commitment,
    ) -> Result<bool, PCSError> {
        todo!()
    }
}
