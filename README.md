# `sigma0-polymath`


This is the first (as far as we know) implementation of the non-universal zk-SNARK described in the paper [Polymath: Groth16 Is Not The Limit](https://ia.cr/2024/916) by [Helger Lipmaa](https://x.com/HLipmaa).

## Using

Add the following to your project's Cargo.toml:
```toml
ark-bls12-381 = { version = "0.4.0" }
ark-crypto-primitives = { version = "0.4.0" }
ark-relations = { version = "0.4.0" }
sigma0-polymath = { git = "https://github.com/sigma0-xyz/polymath" }
```

You will be able to generate proving and verification keys, prove and verify your circuit.

Specify a pairing-friendly curve and Fiat-Shamir transcript implementation you want to use:
```rust
use sigma0_polymath::transcript::MerlinFieldTranscript;

type Polymath = sigma0_polymath::Polymath<Bls12_381, MerlinFieldTranscript<Fr>>;
```

Implement an R1CS circuit:
```rust
struct ExampleCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for ExampleCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;

        let c = self.a.map(|a| self.b.map(|b| a * b)).flatten();
        let c = cs.new_input_variable(|| c.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)
    }
}
```

Generate proving and verifying keys:
```rust
let (pk, vk) = {
    let c = ExampleCircuit::<Fr> { a: None, b: None };
    Polymath::setup(c, &mut rng).unwrap()
};
```

Prove an instance of the circuit:
```rust
let a = rng.gen();
let b = rng.gen();

let product = a * b; // this is the public input

let circuit = ExampleCircuit {
    a: Some(a),
    b: Some(b),
};

let proof = Polymath::prove(&pk, circuit, &mut rng).unwrap();
```

Verify the proof against the public input:
```rust
assert!(Polymath::verify(&vk, &[product], &proof).unwrap());
```

See some end to end examples [here](https://github.com/sigma0-xyz/polymath/tree/main/tests).

## Background

Polymath is a zk-SNARK for SAP ("Square Arithmetic Programming") constraint system.
SAP instance $\mathcal{I} = (\mathbb{F}, m_0, \mathbf{U}, \mathbf{W})$ is a system of algebraic constraints that looks like this:

$$
(\mathbf{U}\mathbb{z})^2 = \mathbf{W}\mathbb{z}
$$

where
- matrices $\mathbf{U}, \mathbf{W} \in \mathbb{F}^{n \times m}$ encode the constraints,
    - m is the number of variables
    - n be the number of constraints
- $m_0$ is the number of the public input ( $m_0 \le m$ )
- vector $\mathbb{z} = (\mathbb{x}||\mathbb{w}) \in \mathbb{F}^m$ is a concatenation of public input $\mathbb{x}\in\mathbb{F}^{m_0}$ and witness $\mathbb{w}\in\mathbb{F}^{m - m_0}$,
- vector $\mathbb{x}\in\mathbb{F}^{m_0}$, by convention, has $1$ as it's first element: $\mathbb{x}_0 = 1$,
- $(\mathbf{U}\mathbb{z})^2$ is element-wise squaring of the vector $\mathbf{U}\mathbb{z}$ elements (Hadamard product).

This is slightly different from the most widespread constraint system R1CS:

$$
\mathbf{A}\mathbb{z} ∘ \mathbf{B}\mathbb{z} = \mathbf{C}·\mathbb{z}
$$

Both systems can represent the same constraints, thanks to the fact that multiplication can be reformulated via squaring with addition (and scaling):

$$
a·b = \frac{(a + b)^2 - (a - b)^2}4
$$

This implementation uses this fact to transform R1CS into SAP, making it a "drop-in" Groth16 replacement.

## License

This library is licensed under either of the following licenses, at your discretion.

* Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
