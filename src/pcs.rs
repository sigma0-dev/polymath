use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, PrimeGroup, ScalarMul, VariableBaseMSM};
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::{clone::Clone, fmt::Debug, rand::Rng};

use crate::Transcript;

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
    type Polynomial: Polynomial<F>;
    type Commitment: Clone
        + Copy
        + Eq
        + PrimeGroup<ScalarField = F>
        + ScalarMul
        + VariableBaseMSM
        + Debug
        + CanonicalSerialize
        + CanonicalDeserialize;
    type EvalProof: Clone
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

    fn setup(
        max_degree: usize,
        trapdoors: &[F; 2],
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
        t: &mut Self::Transcript,
        srs: &Self::VerifyingKey,
        commitments: &[Self::Commitment],
        point: F,
        values: &[F],
        proof: &Self::Commitment,
    ) -> Result<bool, PCSError>;
}

#[derive(Clone)]
pub struct KZG<E: Pairing, P: Polynomial<E::ScalarField>, T: Transcript<Challenge = E::ScalarField>>
{
    _ept: PhantomData<(E, P, T)>,
}

#[derive(Clone, Copy, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGCommittingKey<E: Pairing> {
    _e: PhantomData<E>,
}

#[derive(Clone, Copy, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZGVerifyingKey<E: Pairing> {
    /// `[1]₁` - the `G1` group generator.
    pub one_g1: E::G1Affine,
    /// `[1]₂` - the `G2` group generator.
    pub one_g2: E::G2Affine,
    /// `[x]₂` - the `x` trapdoor (toxic random secret) hidden in `G2`.
    pub x_g2: E::G2Affine,
    /// `[z]₂` - the `z` trapdoor (toxic random secret) hidden in `G2`.
    pub z_g2: E::G2Affine,
}

impl<E: Pairing, P: Polynomial<E::ScalarField>, T: Transcript<Challenge = E::ScalarField>>
    UnivariatePCS<E::ScalarField> for KZG<E, P, T>
{
    type Polynomial = P;
    type Commitment = E::G1;
    type EvalProof = E::G1;
    type CommittingKey = KZGCommittingKey<E>;
    type VerifyingKey = KZGVerifyingKey<E>;
    type Transcript = T;

    fn setup(
        max_degree: usize,
        trapdoors: &[E::ScalarField; 2],
    ) -> Result<(Self::CommittingKey, Self::VerifyingKey), PCSError> {
        let &[x, z] = trapdoors;
        Ok((
            KZGCommittingKey {
                _e: Default::default(), // TODO return the actual committing key
            },
            KZGVerifyingKey {
                one_g1: E::G1Affine::generator(),
                one_g2: E::G2Affine::generator(),
                x_g2: (E::G2Affine::generator() * x).into(),
                z_g2: (E::G2Affine::generator() * z).into(),
            },
        ))
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
