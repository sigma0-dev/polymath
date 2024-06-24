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
    /// `n` - the domain size. Must be a power of 2.
    pub n: u64,
    /// `m₀` - the public input subdomain size. Must be a power of 2.
    pub m0: u64,
    /// `𝜎 = n + 3` - the exponent for "virtual" trapdoor `y = x^𝜎`
    pub sigma: u64,
    /// `𝜔` - root of unity, element of the domain group: `X^n - 1 = 0`,
    /// `𝜔^(j·n) = 1`
    pub omega: E::ScalarField,
    /// `𝜈 = 𝜔^(n/m₀)` - root of unity, element of the public input subdomain group: `X^m₀ - 1 = 0`,
    /// `𝜈^(j·m₀) = 1`
    pub nu: E::ScalarField,
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
