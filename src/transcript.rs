use ark_ff::Field;
use ark_std::convert::AsRef;
use ark_std::marker::PhantomData;

pub trait Transcript: Send + Clone {
    type Challenge: Send + Clone;

    /// Create a new transcript with the specified name.
    fn new(name: &'static [u8]) -> Self;

    /// Apply a domain separator to the transcript.
    fn domain_separate(&mut self, label: &'static [u8]);

    /// Append a message to the transcript.
    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M);

    /// Produce a challenge.
    ///
    /// Implementors MUST update the transcript as it does so, preventing the same challenge from
    /// being generated multiple times.
    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;

    /// Produce a RNG seed.
    ///
    /// Helper function for parties needing to generate random data from an agreed upon state.
    ///
    /// Implementors MAY internally call the challenge function for the needed bytes, and accordingly
    /// produce a transcript conflict between two transcripts, one which called challenge(label) and
    /// one which called rng_seed(label) at the same point.
    fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
}

#[derive(Clone)]
pub struct FieldChallengeTranscript<F: Field> {
    _f: PhantomData<F>,
}

impl<F: Field> Transcript for FieldChallengeTranscript<F> {
    type Challenge = F;

    fn new(name: &'static [u8]) -> Self {
        todo!()
    }

    fn domain_separate(&mut self, label: &'static [u8]) {
        todo!()
    }

    fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
        todo!()
    }

    fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
        todo!()
    }

    fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
        todo!()
    }
}
