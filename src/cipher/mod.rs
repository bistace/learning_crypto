/// A Cipher is a set of algorithms for performing encryption or decryption.
/// The `encrypt` method is used to convert plain text into cipher text.
/// The `decrypt` method is used to convert cipher text back into plain text.

/// The Cipher trait defines a common interface for encryption and decryption operations.
pub trait Cipher {
    /// Encrypts the given plain text and returns the cipher text.
    /// # Arguments
    /// * `plain_text` - A string slice that holds the plain text to be encrypted.
    /// # Returns
    /// * A String holding the cipher text.
    fn encrypt(&self, plain_text: &str) -> String;

    /// Decrypts the given cipher text and returns the plain text.
    /// # Arguments
    /// * `cipher_text` - A string slice that holds the cipher text to be decrypted.
    /// # Returns
    /// * A String holding the plain text.
    fn decrypt(&self, cipher_text: &str) -> String;
}
