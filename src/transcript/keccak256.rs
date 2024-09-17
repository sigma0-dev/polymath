use super::Transcript;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use sha3::{Digest, Keccak256};

/// Transcript with `keccak256` hash function from sh3 crate.
#[derive(Clone)]
pub struct Keccak256Transcript<F: PrimeField> {
    pub(crate) transcript: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Transcript for Keccak256Transcript<F> {
    type Challenge = F;

    fn new(name: &'static [u8]) -> Self {
        Self {
            transcript: vec![],
            _f: Default::default(),
        }
    }

    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
        self.transcript.extend_from_slice(label);
        self.transcript.extend_from_slice(message.as_ref());
    }

    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
        let mut hasher = Keccak256::new();
        hasher.update(&self.transcript);
        hasher.update(label);
        let buf = hasher.finalize();
        let challenge = F::from_be_bytes_mod_order(&buf);

        self.transcript = buf.to_vec();

        challenge
    }
}
