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
    merlin: merlin::Transcript,
    _f: PhantomData<F>,
}

impl<F: Field> Transcript for FieldChallengeTranscript<F> {
    type Challenge = F;

    fn new(name: &'static [u8]) -> Self {
        Self {
            merlin: merlin::Transcript::new(name),
            _f: Default::default(),
        }
    }

    fn domain_separate(&mut self, label: &'static [u8]) {
        todo!()
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

    fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
        todo!()
    }
}
