use std::ops::{Mul, Neg};

use ark_ec::{ScalarMul, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain};
use ark_poly::univariate::DensePolynomial;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::iterable::Iterable;
use ark_std::rand::RngCore;
use ark_std::Zero;

use crate::{Polymath, PolymathError, Proof, ProvingKey, Transcript};
use crate::common::m_at;
use crate::pcs::UnivariatePCS;

type D<F> = Radix2EvaluationDomain<F>;

impl<F: PrimeField, T, PCS> Polymath<F, T, PCS>
where
    T: Transcript<Challenge = F>,
    PCS: UnivariatePCS<F, Transcript = T>,
{
    pub(crate) fn create_proof<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<F, PCS>,
        rng: &mut R,
    ) -> Result<Proof<F, PCS>, PolymathError> {
        let prover_time = start_timer!(|| "Polymath::Prover");
        let cs = ConstraintSystem::new_ref();

        // Set the optimization goal
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        // Produce a witness, do not generate matrices
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });

        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        // debug_assert!(cs.is_satisfied().unwrap());
        end_timer!(synthesis_time);

        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);

        let prover = cs.borrow().unwrap();

        println!(
            "instance assignment [1]: {}",
            &prover.instance_assignment[1]
        );

        let proof = Self::create_proof_with_assignment(
            pk,
            &prover.instance_assignment,
            &prover.witness_assignment,
            rng,
        )?;

        end_timer!(prover_time);

        Ok(proof)
    }

    fn create_proof_with_assignment<R: RngCore>(
        pk: &ProvingKey<F, PCS>,
        instance_assignment: &[F],
        witness_assignment: &[F],
        rng: &mut R,
    ) -> Result<Proof<F, PCS>, PolymathError>
    where
        PCS: UnivariatePCS<F, Transcript = T>,
        T: Transcript<Challenge = F>,
    {
        let z = &[
            instance_assignment,
            instance_assignment,
            witness_assignment,
            &Self::compute_y_vec(pk, instance_assignment, witness_assignment),
        ];

        let u_j_by_z_j_coeffs = Self::polynomials_mul_by_z_j(&pk.u_j_polynomials, z);
        let w_j_by_z_j_coeffs = Self::polynomials_mul_by_z_j(&pk.w_j_polynomials, z);

        let u_coeffs = Self::sum_vectors(&u_j_by_z_j_coeffs);
        let w_coeffs = Self::sum_vectors(&w_j_by_z_j_coeffs);

        let u2_coeffs = Self::square_polynomial(&u_coeffs)?;

        let u_poly = DensePolynomial::from_coefficients_vec(u_coeffs);
        let u2_poly = DensePolynomial::from_coefficients_vec(u2_coeffs);
        let w_poly = DensePolynomial::from_coefficients_vec(w_coeffs);

        let num_sap_rows = pk.sap_matrices.size().0;
        let domain = D::new(num_sap_rows).unwrap();

        let numerator_poly = u2_poly + w_poly.neg();
        let (h_poly, rem_poly) = numerator_poly.divide_by_vanishing_poly(domain).unwrap();

        assert!(!h_poly.is_zero() && h_poly.degree() <= domain.size() - 2);
        assert!(rem_poly.is_zero());

        let r_a_poly = DensePolynomial::from_coefficients_vec(vec![F::rand(rng), F::rand(rng)]);
        assert!(r_a_poly.degree() <= 1);

        let a_g1 = Self::compute_a_g1(pk, &u_poly, &r_a_poly);

        let r_g1 = Self::compute_r_g1(pk, &u_poly, &r_a_poly);

        let c_g1 = todo!();

        let a_at_x1 = todo!();

        let d_g1 = todo!();

        Ok(Proof {
            a_g1,
            c_g1,
            a_at_x1,
            d_g1,
        })
    }

    fn sum_vectors(vs: &Vec<Vec<F>>) -> Vec<F> {
        vs.iter().fold(vec![F::zero(); vs[0].len()], |a, b| {
            a.into_iter().zip(b).map(|(a, b)| a + b).collect()
        })
    }

    fn polynomials_mul_by_z_j(polynomials: &Vec<Vec<F>>, z: &[&[F]]) -> Vec<Vec<F>> {
        polynomials
            .iter()
            .zip(0..)
            .map(|(&ref p_coeffs, j)| {
                p_coeffs
                    .iter()
                    .map(move |&v| v * Self::combined_v_at(z, j))
                    .collect()
            })
            .collect()
    }

    fn poly_mul_by(poly: &[F], s: F) -> Vec<F> {
        poly.iter().map(|&v| v * s).collect()
    }

    fn evals<M: Fn(usize, usize) -> F>(n: usize, m: usize, m_at: M, z: &[&[F]]) -> Vec<F> {
        (0..n)
            .map(|i| {
                (0..m)
                    .map(|j| m_at(i, j) * Self::combined_v_at(z, j))
                    .fold(F::zero(), |x, y| x + y)
            })
            .collect()
    }

    fn compute_y_vec(pk: &ProvingKey<F, PCS>, x: &[F], w: &[F]) -> Vec<F> {
        let zero = F::zero();
        let one = F::one();
        let y_m0: Vec<F> = (1..pk.sap_matrices.num_instance_variables)
            .map(|j| {
                let v = one - x[j];
                v * v
            })
            .collect();

        let (a, b) = (&pk.sap_matrices.a, &pk.sap_matrices.b);

        let y_n: Vec<F> = (0..pk.sap_matrices.num_r1cs_constraints)
            .map(|i| {
                let num_r1cs_columns = pk.sap_matrices.num_instance_variables
                    + pk.sap_matrices.num_r1cs_witness_variables;
                let v = (0..num_r1cs_columns)
                    .map(|j| (m_at(a, i, j) - m_at(b, i, j)) * Self::combined_v_at(&[x, w], j))
                    .fold(zero, |x, y| x + y);
                v * v
            })
            .collect();
        vec![vec![F::zero()], y_m0, y_n].concat()
    }

    fn combined_v_at(vectors: &[&[F]], j: usize) -> F {
        let mut j = j;
        for &v in vectors {
            if j < v.len() {
                return v[j];
            }
            j -= v.len();
        }
        unreachable!()
    }

    fn square_polynomial(p_coeffs: &Vec<F>) -> Result<Vec<F>, PolymathError> {
        let squaring_domain: D<F> =
            D::new(p_coeffs.len() * 2).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let mut u = squaring_domain.fft(p_coeffs);

        for i in 0..u.len() {
            u[i] = u[i] * u[i];
        }

        squaring_domain.ifft_in_place(&mut u); // u is now a coeffs vector

        Ok(u)
    }

    fn compute_a_g1(
        pk: &ProvingKey<F, PCS>,
        u_poly: &DensePolynomial<F>,
        r_a_poly: &DensePolynomial<F>,
    ) -> PCS::Commitment {
        let u_g1 = Self::compute_in_g1(u_poly, &pk.x_powers_g1);
        let r_a_y_alpha_g1 = Self::compute_in_g1(r_a_poly, &pk.x_powers_y_alpha_g1);
        u_g1 + r_a_y_alpha_g1
    }

    fn compute_r_g1(
        pk: &ProvingKey<F, PCS>,
        u_poly: &DensePolynomial<F>,
        r_a_poly: &DensePolynomial<F>,
    ) -> PCS::Commitment {
        let two = F::one() + F::one();

        // r_a is degree 1, so naive mul is cheaper than via FFTs
        let two_r_a_by_u_poly = u_poly.naive_mul(r_a_poly).mul(two);
        let two_r_a_by_u_g1 = Self::compute_in_g1(&two_r_a_by_u_poly, &pk.x_powers_g1);

        let r_a_square_poly = r_a_poly.naive_mul(r_a_poly);
        let r_a_square_y_alpha_g1 = Self::compute_in_g1(&r_a_square_poly, &pk.x_powers_y_alpha_g1);

        let r_a_y_gamma_g1 = Self::compute_in_g1(r_a_poly, &pk.x_powers_y_gamma_g1);

        two_r_a_by_u_g1 + r_a_square_y_alpha_g1 + r_a_y_gamma_g1
    }

    fn compute_in_g1(
        poly: &DensePolynomial<F>,
        g1_monomials: &Vec<PCS::Commitment>,
    ) -> PCS::Commitment {
        let (gs, cs): (Vec<_>, Vec<_>) = poly
            .coeffs
            .iter()
            .zip(0..)
            .filter_map(|(&coeff, i)| match coeff.is_zero() {
                true => None,
                false => Some((
                    <PCS::Commitment as ScalarMul>::MulBase::from(g1_monomials[i]),
                    coeff,
                )),
            })
            .unzip();
        let u_g1 = VariableBaseMSM::msm_unchecked(gs.as_slice(), cs.as_slice());
        u_g1
    }
}
