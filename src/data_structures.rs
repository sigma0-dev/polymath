use ark_ff::{FftField, Field};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::generator::SAPMatrices;
use crate::pcs::{HasPCSCommittingKey, HasPCSVerifyingKey, UnivariatePCS};

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
    pub d_g1: PCS::EvalProof,
}

////////////////////////////////////////////////////////////////////////////////

/// Verification key in the Polymath zkSNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey<F: Field, PCS: UnivariatePCS<F>> {
    pub pcs_vk: PCS::VerifyingKey,
    /// `n` - the domain size. Must be a power of 2.
    pub n: u64,
    /// `m₀` - the public input subdomain size.
    pub m0: u64,
    /// `𝜎 = n + 3` - the exponent for "virtual" trapdoor `y = x^𝜎`
    pub sigma: u64,
    /// `𝜔` - root of unity, element of the domain group: `X^n - 1 = 0`,
    /// `𝜔^(j·n) = 1`
    pub omega: F,
}

// TODO embed PCSVerifying key instead of hardcoding its elements

impl<F: Field, PCS: UnivariatePCS<F>> HasPCSVerifyingKey<F, PCS> for VerifyingKey<F, PCS> {
    fn get_pcs_vk(&self) -> &PCS::VerifyingKey {
        &self.pcs_vk
    }
}

////////////////////////////////////////////////////////////////////////////////

/// Proving key for the Polymath zkSNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey<F: FftField, PCS: UnivariatePCS<F>> {
    pub pcs_ck: PCS::CommittingKey,
    /// The underlying verification key.
    pub vk: VerifyingKey<F, PCS>,
    pub sap_matrices: SAPMatrices<F>,
    pub u_j_polynomials: Vec<Vec<F>>,
    pub w_j_polynomials: Vec<Vec<F>>,
    /// `[(xⁱ)ᵢ]₁` - powers of `x` in `G1`.
    pub x_powers_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·y^𝛼)ᵢ]₁` - powers of `x` multiplied by `y^𝛼` in `G1`.
    pub x_powers_y_alpha_g1: Vec<PCS::Commitment>,
    /// `[(xⁱ·y^𝛾)ᵢ]₁` - powers of `x` multiplied by `y^𝛾` in `G1`.
    pub x_powers_y_gamma_g1: Vec<PCS::Commitment>,
    /// `[((uⱼ(x)·y^𝛾 + wⱼ(x))/y^𝛼)ⱼ]₁` - linear combinations of `uⱼ(x)` and `wⱼ(x)` divided by `y^𝛼` in `G1`.
    pub uw_j_lcs_by_y_alpha_g1: Vec<PCS::Commitment>,
    // TODO there's more
}

// TODO embed PCSCommittingKey key instead of hardcoding its elements

impl<F: FftField, PCS: UnivariatePCS<F>> HasPCSCommittingKey<F, PCS> for ProvingKey<F, PCS> {
    fn get_pcs_ck(&self) -> &PCS::CommittingKey {
        &self.pcs_ck
    }
}
