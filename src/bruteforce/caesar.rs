use anyhow::Result;
use std::collections::HashSet;

use crate::cipher::caesar::Caesar;
use crate::cipher::Cipher;

use super::BruteForce;

/// Implementation of BruteForce for Caesar cipher.
/// This implementation uses a list of words to brute force the Caesar cipher.
/// Returns the most likely decrypted text.
impl BruteForce for Caesar {
    fn brute_force(&self, cipher_text: &str) -> Result<String> {
        let word_list = word_list_to_map("datasets/english_1000.txt")?;

        let mut max_unique_word_count = 0;
        let mut most_likely_decoded = String::new();
        for i in 0..25 {
            let caesar = Caesar::new(i, false);
            let decoded = caesar.decrypt(cipher_text)?;

            let mut unique_word_count = 0;
            for word in word_list.iter() {
                if decoded.contains(word) {
                    unique_word_count += 1;
                }
            }

            if unique_word_count > max_unique_word_count {
                max_unique_word_count = unique_word_count;
                most_likely_decoded = decoded;
            }
        }

        Ok(most_likely_decoded)
    }
}

fn word_list_to_map(path: &str) -> Result<HashSet<String>> {
    Ok(HashSet::from_iter(
        std::fs::read_to_string(path)?
            .lines()
            .map(|l| l.to_string().to_ascii_uppercase()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brute_force_short() {
        let caesar = Caesar::new(3, false);
        let expected = "instant enemy".to_ascii_uppercase();
        let cipher_text = caesar.encrypt(&expected).unwrap();
        let result = caesar.brute_force(&cipher_text).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_brute_force_long() {
        let caesar = Caesar::new(3, false);
        let expected = std::str::from_utf8(include_bytes!("../../datasets/wikipedia_england.txt"))
            .unwrap()
            .to_ascii_uppercase();
        let cipher_text = caesar.encrypt(&expected).unwrap();
        let result = caesar.brute_force(&cipher_text).unwrap();
        assert_eq!(result, expected);
    }
}
