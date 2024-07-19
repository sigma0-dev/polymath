use ark_ec::pairing::Pairing;
use ark_std::fmt::Debug;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::common::SAPMatrices;

/// Proof in the Polymath zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: Pairing> {
    /// `[a]₁` - commitment to `A(X)`.
    pub a_g1: E::G1Affine,
    /// `[c]₁` - commitment to `C(X)`.
    pub c_g1: E::G1Affine,
    /// `A(x1)` - evaluation of `A(X)` at point `x1`.
    pub a_at_x1: E::ScalarField,
    /// `[d]₁` - commitment to quotient polynomial `D(X)`.
    pub d_g1: E::G1Affine,
}

////////////////////////////////////////////////////////////////////////////////

/// Verification key for the pairing check.
#[derive(Clone, Copy, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PairingVK<E: Pairing> {
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
pub struct VerifyingKey<E: Pairing> {
    /// Group elements for the pairing check.
    pub e: PairingVK<E>,
    /// `n` - the domain size. Must be a power of 2.
    pub n: u64,
    /// `m₀` - public input size (doesn't need to be a power of 2).
    pub m0: u64,
    /// `𝜎 = n + 3` - the exponent for "virtual" trapdoor `y = x^𝜎`
    pub sigma: u64,
    /// `𝜔` - root of unity, element of the domain group: `X^n - 1 = 0`,
    /// `𝜔^(j·n) = 1` for any `j`
    pub omega: E::ScalarField,
}

////////////////////////////////////////////////////////////////////////////////

/// Proving key for the Polymath zkSNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// SAP (square arithmetic program) matrices derived from R1CS matrices.
    pub sap_matrices: SAPMatrices<E::ScalarField>,
    /// `[(xⁱ)ᵢ]₁` - powers of `x` in `G1`.
    pub x_powers_g1: Vec<E::G1Affine>,
    /// `[(xⁱ·y^𝛼)ᵢ]₁` - powers of `x` multiplied by `y^𝛼` in `G1`.
    pub x_powers_y_alpha_g1: Vec<E::G1Affine>,
    /// `[(xⁱ·Z_H(x)/(y^𝛼))ᵢ]₁` - powers of `x` multiplied by `Z_H(x)/(y^𝛼)` in
    /// `G1`.
    pub x_powers_zh_by_y_alpha_g1: Vec<E::G1Affine>,
    /// `[(xⁱ·y^𝛾)ᵢ]₁` - powers of `x` multiplied by `y^𝛾` in `G1`.
    pub x_powers_y_gamma_g1: Vec<E::G1Affine>,
    /// `[(xⁱ·y^𝛾·z)ᵢ]₁` - powers of `x` multiplied by `y^𝛾·z` in `G1`.
    pub x_powers_y_gamma_z_g1: Vec<E::G1Affine>,
    /// `[((uⱼ(x)·y^𝛾 + wⱼ(x))/y^𝛼)ⱼ| j = i + m₀, i ∈ [0, m-m₀)]₁` - linear
    /// combinations of `uⱼ(x)` and `wⱼ(x)` divided by `y^𝛼` in `G1` for indices
    /// of the witness vector.
    pub uj_wj_lcs_by_y_alpha_g1: Vec<E::G1Affine>,
}
