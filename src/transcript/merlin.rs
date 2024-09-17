use crate::Transcript;
use ark_ff::Field;
use std::marker::PhantomData;

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
