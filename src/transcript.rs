//! A simplified version of `flexible-transcript`.

use ark_ff::Field;
use ark_std::{convert::AsRef, marker::PhantomData};

/// Transcript to produce Fiat-Shamir challenges.
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

/// Transcript implementation producing field values as challenges using `merlin::Transcript`.
#[derive(Clone)]
pub struct MerlinFieldTranscript<F: Field> {
    /// The underlying `merlin` transcript implementation.
    pub merlin: merlin::Transcript,
    _f: PhantomData<F>,
}

impl<F: Field> Transcript for MerlinFieldTranscript<F> {
    type Challenge = F;

    fn new(name: &'static [u8]) -> Self {
        Self {
            merlin: merlin::Transcript::new(name),
            _f: Default::default(),
        }
    }

    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
        self.merlin.append_message(label, message.as_ref());
    }

    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
        let mut r = None;
        while r.is_none() {
            let mut buf = [0; 64];
            self.merlin.challenge_bytes(label, &mut buf);
            r = F::from_random_bytes(buf.as_ref());
        }
        r.unwrap()
    }
}
