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
        let word_list = load_word_list("datasets/english_1000.txt")?;

        (0..25)
            .filter_map(|i| {
                let caesar = Caesar::new(i, false);
                let decoded = match caesar.decrypt(cipher_text) {
                    Ok(decoded) => decoded,
                    Err(_) => return None,
                };
                let unique_word_count = word_list
                    .iter()
                    .filter(|&word| decoded.contains(word))
                    .count();
                Some((unique_word_count, decoded))
            })
            .max_by_key(|(count, _)| *count)
            .map(|(_, decoded)| decoded)
            .ok_or_else(|| anyhow::anyhow!("No valid decryption found"))
    }
}

fn load_word_list(path: &str) -> Result<HashSet<String>> {
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
