use super::Transcript;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use blake3::Hasher;

/// Transcript with `Blake3` hash function from sh3 crate.
#[derive(Clone)]
pub struct Blake3Transcript<F: PrimeField> {
    pub(crate) transcript: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Transcript for Blake3Transcript<F> {
    type Challenge = F;

    fn new(name: &'static [u8]) -> Self {
        Self {
            transcript: vec![],
            _f: Default::default(),
        }
    }

    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
        // We remove the labels for better efficiency
        self.transcript.extend_from_slice(label);
    }

    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
        let mut hasher = Hasher::new();
        hasher.update(&self.transcript);
        let buf = hasher.finalize();
        let challenge = F::from_be_bytes_mod_order(buf.as_bytes());

        self.append_message(label, &&challenge.into_bigint().to_bytes_be());

        challenge
    }
}
