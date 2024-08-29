use ark_ec::{pairing::Pairing, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial, SparsePolynomial},
    DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::{cfg_into_iter, iterable::Iterable, ops::Mul, rand::RngCore, Zero};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    common::{m_at, B_POLYMATH, MINUS_ALPHA, MINUS_GAMMA},
    Polymath, PolymathError, Proof, ProvingKey, Transcript,
};

type D<F> = Radix2EvaluationDomain<F>;

impl<F: PrimeField, E, T> Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
    pub(crate) fn create_proof<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        pk: &ProvingKey<E>,
        rng: &mut R,
    ) -> Result<Proof<E>, PolymathError> {
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
        pk: &ProvingKey<E>,
        instance_assignment: &[F],
        witness_assignment: &[F],
        rng: &mut R,
    ) -> Result<Proof<E>, PolymathError>
    where
        T: Transcript<Challenge = F>,
    {
        let z = &[
            instance_assignment,
            instance_assignment,
            witness_assignment,
            &Self::compute_y_vec(pk, instance_assignment, witness_assignment),
        ];

        let (num_constraints, num_columns) = pk.sap_matrices.size(); // (rows, columns) in U and W matrices
        let domain = D::new(num_constraints).unwrap();

        let n = domain.size();

        let uj_poly_evals = Self::poly_evals(n, num_columns, |i, j| pk.sap_matrices.u(i, j));
        let wj_poly_evals = Self::poly_evals(n, num_columns, |i, j| pk.sap_matrices.w(i, j));

        let uj_x_zj_evals = Self::polynomials_mul_by_z_j(&uj_poly_evals, z);
        let wj_x_zj_evals = Self::polynomials_mul_by_z_j(&wj_poly_evals, z);

        let u_evals = Self::sum_vectors(&uj_x_zj_evals);
        let u_coeffs = Self::poly_coeffs(domain, u_evals);
        let w_evals = Self::sum_vectors(&wj_x_zj_evals);
        let w_coeffs = Self::poly_coeffs(domain, w_evals);

        let u2_coeffs = Self::square_polynomial(&u_coeffs)?;

        let u_poly = DensePolynomial::from_coefficients_vec(u_coeffs);
        let u2_poly = DensePolynomial::from_coefficients_vec(u2_coeffs);
        let w_poly = DensePolynomial::from_coefficients_vec(w_coeffs);

        let h_numerator_poly = u2_poly + -w_poly;
        let (h_poly, rem_poly) = h_numerator_poly.divide_by_vanishing_poly(domain);

        assert!(!h_poly.is_zero() && h_poly.degree() <= n - 2);
        assert!(rem_poly.is_zero());

        let r_a_poly = DensePolynomial::from_coefficients_vec(vec![F::rand(rng), F::rand(rng)]);
        assert!(r_a_poly.degree() <= 1);

        assert!(u_poly.degree() < n);
        let a_g1 = Self::compute_a_g1(pk, &u_poly, &r_a_poly);

        let r_g1 = Self::compute_r_g1(pk, &u_poly, &r_a_poly);

        let h_zh_by_y_alpha_g1 = Self::msm(&h_poly.coeffs, &pk.x_powers_zh_by_y_alpha_g1);

        let zj_mul_uj_wj_lcs_by_y_alpha_g1 =
            Self::msm(&z[1..].concat(), &pk.uj_wj_lcs_by_y_alpha_g1);

        let c_g1 = zj_mul_uj_wj_lcs_by_y_alpha_g1 + h_zh_by_y_alpha_g1 + r_g1;

        let mut t = T::new(B_POLYMATH);
        let x1 = Self::compute_x1(&mut t, instance_assignment, &[a_g1.into(), c_g1.into()])?;

        let y1 = Self::compute_y1(x1, pk.vk.sigma);

        let y1_alpha = Self::neg_power(y1, MINUS_ALPHA);

        let a_at_x1 = u_poly.evaluate(&x1) + r_a_poly.evaluate(&x1) * y1_alpha;

        let y1_gamma = Self::neg_power(y1, MINUS_GAMMA);
        let pi_at_x1 = Self::compute_pi_at_x1(&pk.vk, instance_assignment, x1, y1_gamma);

        // compute c_at_x1
        let c_at_x1 = Self::compute_c_at_x1(y1_gamma, y1_alpha, a_at_x1, pi_at_x1);

        // compute batch commitment

        let u_poly = SparsePolynomial::from(u_poly);
        let r_a_poly = SparsePolynomial::from(r_a_poly);

        let u_x_by_y_gamma_poly =
            Self::mul_by_x_power(&u_poly, (pk.vk.sigma * MINUS_GAMMA) as usize);

        let r_a_x_y_alpha_by_y_gamma_poly = Self::mul_by_x_power(
            &r_a_poly,
            (pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA)) as usize,
        );
        let a_x_by_y_gamma_poly = u_x_by_y_gamma_poly + r_a_x_y_alpha_by_y_gamma_poly;

        let r_x_by_y_gamma_poly = Self::compute_r_x_by_y_gamma_poly(pk, &u_poly, r_a_poly);

        let m0 = instance_assignment.len();
        let zj_uj_evals = &uj_x_zj_evals[m0..];
        let zj_wj_evals = &wj_x_zj_evals[m0..];

        let witness_u_x_evals = Self::sum_vectors(zj_uj_evals);
        let witness_u_x_coeffs = Self::poly_coeffs(domain, witness_u_x_evals);
        let witness_u_x_poly = DensePolynomial::from_coefficients_vec(witness_u_x_coeffs);

        let witness_w_x_evals = Self::sum_vectors(zj_wj_evals);
        let witness_w_x_coeffs = Self::poly_coeffs(domain, witness_w_x_evals);
        let witness_w_x_poly = DensePolynomial::from_coefficients_vec(witness_w_x_coeffs);

        let witness_u_x_by_y_alpha_poly = Self::mul_by_x_power(
            &SparsePolynomial::from(witness_u_x_poly),
            (pk.vk.sigma * MINUS_ALPHA) as usize,
        );
        let witness_w_x_by_y_alpha_y_gamma_poly = Self::mul_by_x_power(
            &SparsePolynomial::from(witness_w_x_poly),
            (pk.vk.sigma * (MINUS_ALPHA + MINUS_GAMMA)) as usize,
        );

        let h_x_zh_x_by_y_alpha_y_gamma_poly = Self::mul_by_x_power(
            &SparsePolynomial::from(h_numerator_poly),
            (pk.vk.sigma * (MINUS_ALPHA + MINUS_GAMMA)) as usize,
        );

        let c_x_by_y_gamma_poly = witness_u_x_by_y_alpha_poly
            + witness_w_x_by_y_alpha_y_gamma_poly
            + h_x_zh_x_by_y_alpha_y_gamma_poly
            + r_x_by_y_gamma_poly;

        // compute H(X) = (A(X)·(Y^-𝛾) + x₂·C(X)·(Y^-𝛾)) - (A(x₁)·(Y^-𝛾) - x₂·C(x₁)·(Y^-𝛾))/(X - x₁)

        let x2 = Self::compute_x2(&mut t, &x1, &[a_at_x1, c_at_x1])?;

        let y_to_minus_gamma_poly = SparsePolynomial::from_coefficients_slice(&[(
            (pk.vk.sigma * MINUS_GAMMA) as usize,
            F::one(),
        )]);

        let a_at_x1_by_y_gamma_poly = &y_to_minus_gamma_poly * a_at_x1;
        let c_at_x1_by_y_gamma_poly = &y_to_minus_gamma_poly * c_at_x1;

        // debug_assert_eq!(
        //     dbg!(a_at_x1_by_y_gamma_poly.evaluate(&x1) * y1_gamma),
        //     a_at_x1
        // );
        // debug_assert_eq!(dbg!(a_x_by_y_gamma_poly.evaluate(&x1) * y1_gamma), a_at_x1);
        // debug_assert_eq!(
        //     dbg!(c_at_x1_by_y_gamma_poly.evaluate(&x1) * y1_gamma),
        //     c_at_x1
        // );
        // debug_assert_eq!(dbg!(c_x_by_y_gamma_poly.evaluate(&x1) * y1_gamma), c_at_x1);

        // TODO get rid of conversion back and forth - divide sparse poly directly
        let (d_x_by_y_gamma_poly, rem_poly) = DenseOrSparsePolynomial::from(
            a_x_by_y_gamma_poly
                + &c_x_by_y_gamma_poly * x2
                + -a_at_x1_by_y_gamma_poly
                + -(&c_at_x1_by_y_gamma_poly * x2),
        )
        .divide_with_q_and_r(&DenseOrSparsePolynomial::from(
            DensePolynomial::from_coefficients_slice(&[-x1, F::one()]),
        ))
        .unwrap();
        assert!(rem_poly.is_zero());
        assert!(
            d_x_by_y_gamma_poly.degree()
                <= 2 * (n - 1) + (pk.vk.sigma * (MINUS_ALPHA + MINUS_GAMMA)) as usize
        );

        // compute [d]₁ = [D(X)·z] = [(D(X)·(Y^-𝛾))·(Y^𝛾)·z]₁

        let d_g1 = Self::msm(&d_x_by_y_gamma_poly.coeffs, &pk.x_powers_y_gamma_z_g1);

        Ok(Proof {
            a_g1: a_g1.into(),
            c_g1: c_g1.into(),
            a_at_x1,
            d_g1: d_g1.into(),
        })
    }

    fn poly_coeffs<D: EvaluationDomain<F>>(domain: D, evals: Vec<F>) -> Vec<F> {
        let mut result = evals;
        domain.ifft_in_place(&mut result);
        result
    }

    fn poly_evals<M>(n: usize, m: usize, m_ij: M) -> Vec<Vec<F>>
    where
        M: Fn(usize, usize) -> F + Sync,
    {
        cfg_into_iter!(0..m)
            .map(|j| cfg_into_iter!(0..n).map(|i| m_ij(i, j)).collect())
            .collect()
    }

    fn mul_by_x_power(poly: &SparsePolynomial<F>, power_of_x: usize) -> SparsePolynomial<F> {
        SparsePolynomial::from_coefficients_vec(
            poly.iter().map(|(i, c)| (i + power_of_x, *c)).collect(),
        )
    }

    fn sum_vectors(vs: &[Vec<F>]) -> Vec<F> {
        vs.iter().fold(vec![F::zero(); vs[0].len()], |a, b| {
            a.into_iter().zip(b).map(|(a, b)| a + b).collect()
        })
    }

    fn polynomials_mul_by_z_j(polynomials: &[Vec<F>], z: &[&[F]]) -> Vec<Vec<F>> {
        polynomials
            .iter()
            .zip(0..)
            .map(|(p_coeffs, j)| {
                p_coeffs
                    .iter()
                    .map(move |&c| c * Self::combined_v_at(z, j))
                    .collect()
            })
            .collect()
    }

    fn compute_y_vec(pk: &ProvingKey<E>, x: &[F], w: &[F]) -> Vec<F> {
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
        [vec![F::zero()], y_m0, y_n].concat()
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

    fn square_polynomial(p_coeffs: &[F]) -> Result<Vec<F>, PolymathError> {
        let squaring_domain: D<F> =
            D::new(p_coeffs.len() * 2).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let mut u = squaring_domain.fft(p_coeffs); // u is a vector of evaluations

        for ui in &mut u {
            *ui *= *ui;
        }

        squaring_domain.ifft_in_place(&mut u); // u is now a coeffs vector

        Ok(u)
    }

    fn compute_a_g1(
        pk: &ProvingKey<E>,
        u_poly: &DensePolynomial<F>,
        r_a_poly: &DensePolynomial<F>,
    ) -> E::G1 {
        let u_g1 = Self::msm(&u_poly.coeffs, &pk.x_powers_g1);
        let r_a_y_alpha_g1 = Self::msm(&r_a_poly.coeffs, &pk.x_powers_y_alpha_g1);
        u_g1 + r_a_y_alpha_g1
    }

    fn compute_r_g1(
        pk: &ProvingKey<E>,
        u_poly: &DensePolynomial<F>,
        r_a_poly: &DensePolynomial<F>,
    ) -> E::G1 {
        let two = F::one() + F::one();

        // r_a is degree 1, so naive mul is cheaper than via FFTs
        let two_r_a_by_u_poly = u_poly.naive_mul(r_a_poly).mul(two);
        let two_r_a_by_u_g1 = Self::msm(&two_r_a_by_u_poly.coeffs, &pk.x_powers_g1);

        let r_a_square_poly = r_a_poly.naive_mul(r_a_poly);
        let r_a_square_y_alpha_g1 = Self::msm(&r_a_square_poly.coeffs, &pk.x_powers_y_alpha_g1);

        let r_a_y_gamma_g1 = Self::msm(&r_a_poly.coeffs, &pk.x_powers_y_gamma_g1);

        two_r_a_by_u_g1 + r_a_square_y_alpha_g1 + r_a_y_gamma_g1
    }

    fn compute_r_x_by_y_gamma_poly(
        pk: &ProvingKey<E>,
        u_poly: &SparsePolynomial<F>,
        r_a_poly: SparsePolynomial<F>,
    ) -> SparsePolynomial<F> {
        let two = F::one() + F::one();

        let two_r_a_x_u_poly = &u_poly.mul(&r_a_poly) * two;
        let two_r_a_x_u_by_y_gamma_poly =
            Self::mul_by_x_power(&two_r_a_x_u_poly, (pk.vk.sigma * MINUS_GAMMA) as usize);

        let r_a_square_poly = r_a_poly.mul(&r_a_poly);
        let r_a_square_by_y_gamma_minus_alpha_poly = Self::mul_by_x_power(
            &r_a_square_poly,
            (pk.vk.sigma * (MINUS_GAMMA - MINUS_ALPHA)) as usize,
        );

        two_r_a_x_u_by_y_gamma_poly + r_a_square_by_y_gamma_minus_alpha_poly + r_a_poly
    }

    #[inline]
    fn msm(scalars: &Vec<F>, g1_elems: &Vec<E::G1Affine>) -> E::G1 {
        assert!(scalars.len() <= g1_elems.len());

        E::G1::msm_unchecked(g1_elems.as_slice(), scalars.as_slice())
    }
}
