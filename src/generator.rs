use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError, SynthesisMode,
};
use ark_std::{cfg_into_iter, rand::RngCore};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    common::{SAPMatrices, MINUS_ALPHA, MINUS_GAMMA},
    PairingVK, Polymath, PolymathError, ProvingKey, Transcript, VerifyingKey,
};

type D<F> = Radix2EvaluationDomain<F>;

impl<F: PrimeField, E: Pairing, T> Polymath<E, T>
where
    E: Pairing<ScalarField = F>,
    T: Transcript<Challenge = F>,
{
    pub(crate) fn generate_proving_key<C: ConstraintSynthesizer<F>, R: RngCore>(
        circuit: C,
        rng: &mut R,
    ) -> Result<ProvingKey<E>, PolymathError> {
        let setup_time = start_timer!(|| "Polymath::Generator");
        ///////////////////////////////////////////////////////////////////////////

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);

        println!("Constraint synthesis ...");
        // Synthesize the circuit.
        let synthesis_time = start_timer!(|| "Constraint synthesis");
        circuit.generate_constraints(cs.clone())?;
        end_timer!(synthesis_time);
        println!("Constraint synthesis ... Done.");

        println!("Inlining LCs ...");
        let lc_time = start_timer!(|| "Inlining LCs");
        cs.finalize();
        end_timer!(lc_time);
        println!("Inlining LCs ... Done.");

        ///////////////////////////////////////////////////////////////////////////

        let r1cs_matrices = cs.to_matrices().unwrap();
        let sap_matrices = SAPMatrices {
            num_instance_variables: r1cs_matrices.num_instance_variables,
            num_r1cs_witness_variables: r1cs_matrices.num_witness_variables,
            num_r1cs_constraints: r1cs_matrices.num_constraints,
            a: r1cs_matrices.a,
            b: r1cs_matrices.b,
            c: r1cs_matrices.c,
        };

        ///////////////////////////////////////////////////////////////////////////

        let domain_time = start_timer!(|| "Constructing evaluation domain");

        let (num_constraints, num_columns) = sap_matrices.size(); // (rows, columns) in U and W matrices
        let domain = D::new(num_constraints).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        end_timer!(domain_time);
        ///////////////////////////////////////////////////////////////////////////

        let n = domain.size(); // a power of 2
        let m = num_columns;
        let m0 = cs.num_instance_variables();
        let bnd_a: usize = 1;
        let sigma = n + 3;

        let x: F = domain.sample_element_outside_domain(rng);
        let y: F = x.pow([sigma as u64]);
        let y_alpha = y.inverse().unwrap().pow([MINUS_ALPHA]);
        let y_to_minus_alpha = y.pow([MINUS_ALPHA]);
        let y_gamma = y.inverse().unwrap().pow([MINUS_GAMMA]);
        let z: F = domain.sample_element_outside_domain(rng);

        let g1 = E::G1::generator();

        let x_powers_g1 = Self::generate(g1, n + bnd_a - 1, |j| x.pow([j]));

        let x_powers_y_alpha_g1 = Self::generate(g1, 2 * bnd_a, |j| x.pow([j]) * y_alpha);

        let x_powers_y_gamma_g1 = Self::generate(g1, bnd_a, |j| x.pow([j]) * &y_gamma);

        let x_powers_y_gamma_z_g1 = {
            let d_x_by_y_gamma_max_degree =
                2 * (n - 1) + (sigma * (MINUS_ALPHA + MINUS_GAMMA) as usize);
            Self::generate(g1, d_x_by_y_gamma_max_degree, |j| {
                x.pow([j]) * &y_gamma * &z
            })
        };

        let x_powers_zh_by_y_alpha_g1 = {
            let zh_at_x = domain.evaluate_vanishing_polynomial(x);
            Self::generate(g1, n - 2, |j| x.pow([j]) * &zh_at_x * &y_to_minus_alpha)
        };

        let uj_wj_lcs_by_y_alpha_g1 = {
            let l_at_x = domain.evaluate_all_lagrange_coefficients(x);

            Self::generate(g1, m - m0 - 1, |j| {
                let uj_evals: Vec<F> = cfg_into_iter!(0..n)
                    .map(|i| sap_matrices.u(i, j as usize + m0))
                    .collect();
                debug_assert_eq!(uj_evals.len(), l_at_x.len());
                let wj_evals: Vec<F> = cfg_into_iter!(0..n)
                    .map(|i| sap_matrices.w(i, j as usize + m0))
                    .collect();
                debug_assert_eq!(wj_evals.len(), l_at_x.len());

                let uj_x = cfg_iter!(l_at_x)
                    .zip(uj_evals)
                    .map(|(&l, uj)| l * &uj)
                    .sum::<F>();
                let wj_x = cfg_iter!(l_at_x)
                    .zip(wj_evals)
                    .map(|(&l, wj)| l * &wj)
                    .sum::<F>();

                (uj_x * &y_gamma + wj_x) * &y_to_minus_alpha
            })
        };

        let g2 = E::G2::generator();

        let e = PairingVK {
            one_g1: g1.into(),
            one_g2: g2.into(),
            x_g2: (g2 * &x).into(),
            z_g2: (g2 * &z).into(),
        };

        end_timer!(setup_time);

        Ok(ProvingKey {
            vk: VerifyingKey {
                e,
                n: n as u64,
                m0: m0 as u64,
                sigma: sigma as u64,
                omega: domain.group_gen(),
            },
            sap_matrices,

            x_powers_g1,
            x_powers_y_alpha_g1,
            x_powers_y_gamma_g1,
            x_powers_y_gamma_z_g1,
            x_powers_zh_by_y_alpha_g1,
            uj_wj_lcs_by_y_alpha_g1,
        })
    }

    fn generate<G, M>(g: G, max_index: usize, f: M) -> Vec<G::Affine>
    where
        G: CurveGroup,
        M: Fn(u64) -> G::ScalarField,
    {
        (0..max_index + 1)
            .map(|j| (g * f(j as u64)).into())
            .collect()
    }
}
