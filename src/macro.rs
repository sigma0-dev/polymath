/// Takes as input a reference to a data structure implementing `CanonicalSerialize`,
/// and converts it to a series of bytes. Example usage:
/// ```ignore
/// transcript.append_message(b"public_inputs", &to_bytes!(&public_inputs)?);
/// ```
#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = ark_std::vec![];
        ark_serialize::CanonicalSerialize::serialize_compressed($x, &mut buf).map(|_| buf)
    }};
}
