use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;

#[derive(thiserror::Error, Debug)]
pub enum PolymathError {
    #[error(transparent)]
    SynthesisError(#[from] SynthesisError),
    #[error(transparent)]
    SerializationError(#[from] SerializationError),
}
