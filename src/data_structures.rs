use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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

/// Verification key in the Polymath zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<E: Pairing> {
    /// `[1]₁` - the `G1` group generator.
    pub one_g1: E::G1Affine,
    /// `[1]₂` - the `G2` group generator.
    pub one_g2: E::G2Affine,
    /// `[x]₂` - the `x` trapdoor (toxic random secret) hidden in `G2`.
    pub x_g2: E::G2Affine,
    /// `[z]₂` - the `z` trapdoor (toxic random secret) hidden in `G2`.
    pub z_g2: E::G2Affine,
}

////////////////////////////////////////////////////////////////////////////////

/// Preprocessed verification key parameters are supposed to enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PreparedVerifyingKey<E: Pairing> {
    /// The unprepared verification key.
    pub vk: VerifyingKey<E>,
}

////////////////////////////////////////////////////////////////////////////////

/// Proving key for the Polymath zkSNARK.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<E: Pairing> {
    /// The underlying verification key.
    pub vk: VerifyingKey<E>,
    /// `[(xⁱ)ᵢ]₁` - powers of `x` in `G1`.
    pub x_powers_g1: Vec<E::G1Affine>,
    /// `[(xⁱ·y^𝛼)ᵢ]₁` - powers of `x` multiplied by `y^𝛼` in `G1`.
    pub x_powers_y_alpha_g1: Vec<E::G1Affine>,
    /// `[((uⱼ(x)·y^𝛾 + wⱼ(x))/y^𝛼)ⱼ]₁` - linear combinations of `uⱼ(x)` and `wⱼ(x)` divided by `y^𝛼` in `G1`.
    pub uw_j_lcs_by_y_alpha_g1: Vec<E::G1Affine>,
    // TODO there's more
}
