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
        let mut res_bytes: Vec<u8> = Vec::with_capacity(bytes.len());

        for (i, b) in bytes.iter().enumerate() {
            let new_byte = if b.is_ascii_alphabetic() && b.is_ascii_uppercase() {
                // Calculate the new byte value by shifting the ASCII value of the character
                (b - b'A' + self.shift_distance_mod) % 26 + b'A'
            } else {
                // We only handle alphabetic uppercase characters
                eprintln!(
                    "Warning - unhandled character: '{:?}'",
                    plain_text.chars().nth(i)
                );
                *b
            };

            res_bytes.push(new_byte);
        }

        let encoded = std::str::from_utf8(&res_bytes)?;
        Ok(encoded.to_string())
    }

    fn decrypt(&self, cipher_text: &str) -> Result<String> {
        let bytes = cipher_text.as_bytes();
        let mut res_bytes: Vec<u8> = Vec::with_capacity(bytes.len());

        let letter_a_code = b'A' as i16;
        for (i, b) in bytes.iter().enumerate() {
            if !b.is_ascii_alphabetic() || !b.is_ascii_uppercase() {
                eprintln!(
                    "Warning - unhandled character: '{:?}'",
                    cipher_text.chars().nth(i)
                );
                res_bytes.push(*b);
                continue;
            }

            // We need to cast the byte to an i16 because we cannot go below 0 with a
            // standard u8
            let b = *b as i16;
            let new_byte =
                (b - letter_a_code - self.shift_distance_mod as i16).rem_euclid(26) + letter_a_code;
            res_bytes.push(new_byte as u8);
        }

        let decoded = std::str::from_utf8(&res_bytes)?;
        Ok(decoded.to_string())
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

    #[test]
    fn test_decrypt_sd_1() {
        let caesar = Caesar::new(1);
        let cipher_text = "IFMMP XPSME";
        let decrypted = caesar.decrypt(cipher_text).unwrap();

        assert_eq!(decrypted, "HELLO WORLD");
    }

    #[test]
    fn test_decrypt_sd_0() {
        let caesar = Caesar::new(0);
        let cipher_text = "HELLO WORLD";
        let decrypted = caesar.decrypt(cipher_text).unwrap();

        assert_eq!(decrypted, "HELLO WORLD");
    }

    #[test]
    fn test_decrypt_sd_53() {
        let caesar = Caesar::new(53);
        let cipher_text = "IFMMP XPSME";
        let decrypted = caesar.decrypt(cipher_text).unwrap();

        assert_eq!(decrypted, "HELLO WORLD");
    }
}
