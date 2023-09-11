use super::Cipher;

use anyhow::{Context, Result};

/// The Caesar Cipher is one of the simplest and most widely known encryption
/// techniques. It is a type of substitution cipher in which each letter in the
/// plaintext is 'shifted' a certain number of places down the alphabet.
/// For example, with a shift of 1, A would be replaced by B, B would become C,
/// and so on. The method is named after Julius Caesar, who apparently used it
/// to communicate with his generals.
///
/// Our particular version only encodes strings that are uppercase and valid
/// UTF-8 characters.

/// The Caesar struct represents a Caesar cipher with a specific shift distance.
/// The shift distance is the number of places each letter in the plaintext is
/// 'shifted' down the alphabet. The shift_distance_mod is the shift distance
/// modulo 26, to ensure it falls within the range of the alphabet.
pub struct Caesar {
    /// The shift distance for the Caesar cipher.
    pub shift_distance: usize,
    /// The shift distance modulo 26.
    shift_distance_mod: u8,
}

impl Caesar {
    /// Constructs a new Caesar cipher with the specified shift distance.
    /// # Parameters
    /// * `shift_distance` - The number of places to shift each letter in the
    ///   plaintext down the alphabet.
    /// # Returns
    /// A new Caesar cipher with the specified shift distance.
    pub fn new(shift_distance: usize) -> Self {
        let shift_distance_mod: u8 = (shift_distance % 26).try_into().unwrap();

        Self {
            shift_distance,
            shift_distance_mod,
        }
    }
}

impl Cipher for Caesar {
    fn encrypt(&self, plain_text: &str) -> Result<String> {
        let bytes = plain_text.as_bytes();
        let mut res_bytes: Vec<u8> = Vec::with_capacity(plain_text.len());

        for (i, b) in bytes.iter().enumerate() {
            let new_byte = if b.is_ascii_alphabetic() && b.is_ascii_uppercase() {
                // Calculate the new byte value by shifting the ASCII value of the character
                (b - b'A' + self.shift_distance_mod) % 26 + b'A'
            } else {
                // We only handle alphabetic uppercase characters
                eprintln!(
                    "Warning - unhandled character detected: {:?}",
                    plain_text.chars().nth(i)
                );
                *b
            };

            res_bytes.push(new_byte);
        }

        let encoded = std::str::from_utf8(&res_bytes).with_context(|| {
            format!("Failed to encrypt `{plain_text}`: Non-UTF8 characters detected")
        })?;

        Ok(encoded.to_string())
    }

    fn decrypt(&self, cipher_text: &str) -> Result<String> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_sd_1() {
        let caesar = Caesar::new(1);
        let plain_text = "HELLO WORLD";
        let encrypted = caesar.encrypt(plain_text).unwrap();

        assert_eq!(encrypted, "IFMMP XPSME");
    }

    #[test]
    fn test_encrypt_sd_0() {
        let caesar = Caesar::new(0);
        let plain_text = "HELLO WORLD";
        let encrypted = caesar.encrypt(plain_text).unwrap();

        assert_eq!(encrypted, "HELLO WORLD");
    }

    #[test]
    fn test_encrypt_sd_53() {
        let caesar = Caesar::new(53);
        let plain_text = "HELLO WORLD";
        let encrypted = caesar.encrypt(plain_text).unwrap();

        assert_eq!(encrypted, "IFMMP XPSME");
    }
}
