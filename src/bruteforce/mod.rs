/// BruteForce trait defines a method for brute force attacks on ciphers.
pub mod caesar;

use anyhow::Result;

pub trait BruteForce {
    /// Performs a brute force attack on the given cipher text.
    /// # Arguments
    /// * `cipher_text` - A string slice that holds the cipher text to be
    ///   attacked.
    /// # Returns
    /// * A String holding the decrypted text.
    fn brute_force(&self, cipher_text: &str) -> Result<String>;
}
