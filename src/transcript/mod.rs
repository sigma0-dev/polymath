//! A simplified version of `flexible-transcript`.

pub mod keccak256;
pub mod merlin;

use ark_ff::Field;
use ark_std::{convert::AsRef, marker::PhantomData};

/// Transcript to produce Fiat-Shamir challenges.
/// The transcript can be either
/// 1. a Merlin transcript(instantiated with Sha-3/keccak), it's the default transcript
/// 2. a Keccak256 transcript, which is Solidity-friendly transcript(instantiated with Keccak256 hash).
pub trait Transcript: Send + Clone {
    /// The type of Fiat-Shamir challenge produced by the transcript.
    type Challenge: Send + Clone;

    /// Create a new transcript with the specified name.
    fn new(name: &'static [u8]) -> Self;

    /// Append a message to the transcript.
    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M);

    /// Produce a challenge.
    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;
}
