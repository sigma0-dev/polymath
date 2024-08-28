use super::Transcript;
use std::marker::PhantomData;

use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_std::vec::Vec;
use sha3::{Digest, Keccak256};

/// Transcript with `keccak256` hash function.
///
/// It is currently implemented simply as
/// - an append only vector of field elements
///
/// We keep appending new elements to the transcript vector,
/// and when a challenge is generated they are appended too.
///
/// 1. challenge = hash(transcript)
/// 2. transcript = transcript || challenge
#[derive(Clone)]
pub struct SolidityTranscript<F: PrimeField> {
    pub(crate) transcript: Vec<u8>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Transcript for SolidityTranscript<F> {
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
        let mut hasher = Keccak256::new();
        hasher.update(&self.transcript);
        let buf = hasher.finalize();
        let challenge = F::from_be_bytes_mod_order(&buf);

        self.append_message(label, &&challenge.into_bigint().to_bytes_be());

        challenge
    }
}

#[test]
fn test_solidity_keccak() {
    use hex::FromHex;
    use sha3::{Digest, Keccak256};
    let message = "the quick brown fox jumps over the lazy dog".as_bytes();

    let mut hasher = Keccak256::new();
    hasher.update(message);
    let output = hasher.finalize();

    // test example result yanked from smart contract execution
    assert_eq!(
        output[..],
        <[u8; 32]>::from_hex("865bf05cca7ba26fb8051e8366c6d19e21cadeebe3ee6bfa462b5c72275414ec")
            .unwrap()
    );
}
