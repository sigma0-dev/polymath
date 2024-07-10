use ark_ec::pairing::Pairing;
use std::fmt::Debug;
use std::hash::Hash;

use ark_ff::{FftField, Field};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};

use crate::generator::SAPMatrices;
use crate::pcs::{HasPCSVerifyingKey, UnivariatePCS};

/// Proof in the Polymath zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<F: Field, PCS: UnivariatePCS<F>> {
    /// `[a]₁` - commitment to `A(X)`.
    pub a_g1: PCS::Commitment,
    /// `[c]₁` - commitment to `C(X)`.
    pub c_g1: PCS::Commitment,
    /// `A(x1)` - evaluation of `A(X)` at point `x1`.
    pub a_at_x1: F,
    /// `[d]₁` - commitment to quotient polynomial `D(X)`.
    pub d_g1: PCS::Commitment,
}

////////////////////////////////////////////////////////////////////////////////

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

/// Verification key in the Polymath zkSNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<F: Field, E: Pairing> {
    pub vk: KZGVerifyingKey<E>,
    /// `n` - the domain size. Must be a power of 2.
    pub n: u64,
    /// `m₀` - public input size (doesn't need to be a power of 2).
    pub m0: u64,
    /// `𝜎 = n + 3` - the exponent for "virtual" trapdoor `y = x^𝜎`
    pub sigma: u64,
    /// `𝜔` - root of unity, element of the domain group: `X^n - 1 = 0`,
    /// `𝜔^(j·n) = 1` for any `j`
    pub omega: F,
}

////////////////////////////////////////////////////////////////////////////////

/// Proving key for the Polymath zkSNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<F: FftField, E: Pairing, PCS: UnivariatePCS<F>> {
    /// The underlying verification key.
    pub vk: VerifyingKey<F, E>,
    pub sap_matrices: SAPMatrices<F>,
    pub u_j_polynomials: Vec<Vec<F>>,
    pub w_j_polynomials: Vec<Vec<F>>,
    /// `[(xⁱ)ᵢ]₁` - powers of `x` in `G1`.
    pub x_powers_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·y^𝛼)ᵢ]₁` - powers of `x` multiplied by `y^𝛼` in `G1`.
    pub x_powers_y_alpha_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·Z_H(x)/(y^𝛼))ᵢ]₁` - powers of `x` multiplied by `Z_H(x)/(y^𝛼)` in `G1`.
    pub x_powers_zh_by_y_alpha_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·y^𝛾)ᵢ]₁` - powers of `x` multiplied by `y^𝛾` in `G1`.
    pub x_powers_y_gamma_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·y^𝛾·z)ᵢ]₁` - powers of `x` multiplied by `y^𝛾·z` in `G1`.
    pub x_powers_y_gamma_z_g1: Vec<PCS::Commitment>,
    /// `[((uⱼ(x)·y^𝛾 + wⱼ(x))/y^𝛼)ⱼ| j = i + m₀, i ∈ [0, m-m₀)]₁` - linear combinations of `uⱼ(x)` and `wⱼ(x)` divided by `y^𝛼` in `G1` for indices of the witness vector.
    pub uj_wj_lcs_by_y_alpha_g1: Vec<PCS::Commitment>,
    // TODO there's more
}
