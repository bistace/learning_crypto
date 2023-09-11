mod md5;

use anyhow::Result;

/// The `Hasher` trait defines a common interface for all hashing algorithms.
/// Each hasher must implement the `hash` function, which takes a string as
/// input and returns the hashed output as a string.
pub trait Hasher {
    fn hash(&self, text: &str) -> Result<String>;
}
