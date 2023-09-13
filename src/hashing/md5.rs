use crate::hashing::Hasher;

use anyhow::Result;

pub struct MD5 {}

impl Hasher for MD5 {
    fn hash(&self, text: &str) -> Result<String> {
        let padded_text = pad_input(text);

        let table = build_value_table();

        let mut a: u32 = 0x67452301;
        let mut b: u32 = 0xEFCDAB89;
        let mut c: u32 = 0x98BADCFE;
        let mut d: u32 = 0x10325476;

        for chunk in padded_text.chunks_exact(64) {
            let chunk = bytes_to_u32_chunks(chunk);

            let (save_a, save_b, save_c, save_d) = (a, b, c, d);
            (a, b, c, d) = round_1(a, b, c, d, &chunk, &table);
            (a, b, c, d) = round_2(a, b, c, d, &chunk, &table);
            (a, b, c, d) = round_3(a, b, c, d, &chunk, &table);
            (a, b, c, d) = round_4(a, b, c, d, &chunk, &table);

            a = a.wrapping_add(save_a);
            b = b.wrapping_add(save_b);
            c = c.wrapping_add(save_c);
            d = d.wrapping_add(save_d);
        }

        Ok(format!(
            "0x{}",
            [a, b, c, d]
                .iter()
                .map(|&x| format!("{:08x}", x.swap_bytes()))
                .collect::<String>()
        ))
    }
}

/// Builds a value table for the MD5 algorithm.
///
/// The value table in the MD5 algorithm is a precomputed table of 64
/// values. These values are used in the main loop of the algorithm to
/// introduce a nonlinearity and prevent certain types of cryptographic
/// attacks.
///
/// The values are computed using the following formula:
///     T[i] = floor(abs(sin(i)) * 2^32)
/// where i is the index of the value in the table (1-based).
fn build_value_table() -> Vec<u32> {
    let mut table: Vec<u32> = Vec::with_capacity(65);
    table.push(0);

    let coefficient: f64 = (2f64).powf(32.0);
    table.extend((1..=64).map(|i| {
        let i: f64 = i as f64;
        (coefficient * i.sin().abs()) as u32
    }));

    table
}

/// Pads the input text to meet the requirements of the MD5 algorithm.
///
/// The MD5 algorithm requires that the input be a multiple of 512 bits in
/// length. This function pads the input text to meet this requirement by
/// performing the following steps:
/// 1. Convert the input text to bytes.
/// 2. Add a '1' bit just after the input.
/// 3. Add '0' bits until the size in bits modulo 512 is 448.
/// 4. Compute the size in bits of the input and store the resulting u64 as an
///    array of u8.
///
/// # Arguments
///
/// * `text` - A string slice that holds the text to be padded.
///
/// # Returns
///
/// * A vector of bytes representing the padded input.
fn pad_input(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();

    // Add a '1' just after the input
    bytes.push(0b10000000);

    // Add 8 bits until the size in bits modulo 512 is 448
    while ((bytes.len() * 8) % 512) != 448 {
        bytes.push(0);
    }

    // Compute the size in bits of the input and store the resulting u64
    // as an array of u8
    let size_in_bits = 8 * text.len() as u64;
    bytes.extend(u64_to_array_u8(size_in_bits));

    bytes
}

/// Converts a u64 into an array of u8.
///
/// This function takes a u64 as input and converts it into an array of 8 u8s.
/// It does this by shifting the input to the right by a certain number of bits
/// to keep only the rightmost byte. The result is then cast to u8 and stored in
/// the byte array.
/// # Arguments
/// * `size` - A u64 that will be converted into an array of u8.
/// # Returns
/// * An array of 8 u8s representing the input u64.
fn u64_to_array_u8(size: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        // Shift the size to the right by i * 8 bits, effectively moving the byte
        // we are interested in to the rightmost position. Finally, we cast the result
        // to u8 and store it in the byte array
        bytes[i] = (size >> (i * 8)) as u8;
    }

    // Return the byte array
    bytes
}

/// Converts a chunk of u8 values into a vector of u32 values.
///
/// This function takes a reference to a slice of u8 values and converts
/// them into a vector of u32 values. It does this by iterating over the slice
/// and grouping every 4 u8 values into a u32 value. The u32 value is
/// constructed using the from_ne_bytes function, which interprets the u8 values
/// as a native endian integer.
///
/// # Arguments
///
/// * `bytes` - A reference to a slice of u8 values.
///
/// # Returns
///
/// * A vector of u32 values.
fn bytes_to_u32_chunks(bytes: &[u8]) -> Vec<u32> {
    // Initialize an empty vector to hold the u32 values
    let mut chunks: Vec<u32> = Vec::new();

    for chunk in bytes.chunks(4) {
        let u32_value = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        chunks.push(u32_value);
    }

    chunks
}

/// Macro for performing a round operation in the MD5 algorithm.
///
/// This macro takes in three identifiers and three expressions, performs a
/// series of operations including addition, bitwise operations and left
/// rotation, and assigns the result back to the first identifier.
///
/// # Arguments
///
/// * `$a` - An identifier that will hold the result of the operations.
/// * `$b`, `$c`, `$d` - Identifiers used in the operations.
/// * `$func` - An expression representing a function to be applied on `$b`,
///   `$c`, and `$d`.
/// * `$chunk` - An expression representing a chunk of data to be added.
/// * `$table_val` - An expression representing a value from the precomputed
///   table.
/// * `s` - An expression representing the number of bits to left rotate.
macro_rules! round_op {
    ( $a: ident, $b: ident, $c: ident, $d: ident, $func: expr, $chunk: expr, $table_val: expr, $s: expr) => {
        $a = $b.wrapping_add(
            ($a.wrapping_add($func($b, $c, $d))
                .wrapping_add($chunk)
                .wrapping_add($table_val))
            .rotate_left($s),
        )
    };
}

/// Performs the first round of the MD5 algorithm.
///
/// This function takes four u32 values, a slice of u32 chunks, and a slice of
/// u32 table values. It performs a series of operations defined by the MD5
/// algorithm for the first round. The operations include addition, bitwise
/// operations, and left rotation.
///
/// # Arguments
///
/// * `a`, `b`, `c`, `d` - u32 registers used in the operations.
/// * `chunks` - A slice of u32 values representing chunks of data to be
///   processed.
/// * `table` - A slice of u32 values from the precomputed table.
fn round_1(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    chunks: &[u32],
    table: &[u32],
) -> (u32, u32, u32, u32) {
    // Let [abcd k s i] denote the operation
    // a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)

    for i in 0..4 {
        let j = i * 4;
        round_op!(a, b, c, d, f, chunks[j], table[j + 1], 7);
        round_op!(d, a, b, c, f, chunks[j + 1], table[j + 2], 12);
        round_op!(c, d, a, b, f, chunks[j + 2], table[j + 3], 17);
        round_op!(b, c, d, a, f, chunks[j + 3], table[j + 4], 22);
    }

    (a, b, c, d)
}

/// Performs the second round of the MD5 algorithm.
///
/// This function takes four u32 values, a slice of u32 chunks, and a slice of
/// u32 table values. It performs a series of operations defined by the MD5
/// algorithm for the first round. The operations include addition, bitwise
/// operations, and left rotation.
///
/// # Arguments
///
/// * `a`, `b`, `c`, `d` - u32 registers used in the operations.
/// * `chunks` - A slice of u32 values representing chunks of data to be
///   processed.
/// * `table` - A slice of u32 values from the precomputed table.
fn round_2(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    chunks: &[u32],
    table: &[u32],
) -> (u32, u32, u32, u32) {
    // Let [abcd k s i] denote the operation
    // a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)

    round_op!(a, b, c, d, g, chunks[1], table[17], 5);
    round_op!(d, a, b, c, g, chunks[6], table[18], 9);
    round_op!(c, d, a, b, g, chunks[11], table[19], 14);
    round_op!(b, c, d, a, g, chunks[0], table[20], 20);

    round_op!(a, b, c, d, g, chunks[5], table[21], 5);
    round_op!(d, a, b, c, g, chunks[10], table[22], 9);
    round_op!(c, d, a, b, g, chunks[15], table[23], 14);
    round_op!(b, c, d, a, g, chunks[4], table[24], 20);

    round_op!(a, b, c, d, g, chunks[9], table[25], 5);
    round_op!(d, a, b, c, g, chunks[14], table[26], 9);
    round_op!(c, d, a, b, g, chunks[3], table[27], 14);
    round_op!(b, c, d, a, g, chunks[8], table[28], 20);

    round_op!(a, b, c, d, g, chunks[13], table[29], 5);
    round_op!(d, a, b, c, g, chunks[2], table[30], 9);
    round_op!(c, d, a, b, g, chunks[7], table[31], 14);
    round_op!(b, c, d, a, g, chunks[12], table[32], 20);

    (a, b, c, d)
}

/// Performs the third round of the MD5 algorithm.
///
/// This function takes four u32 values, a slice of u32 chunks, and a slice of
/// u32 table values. It performs a series of operations defined by the MD5
/// algorithm for the first round. The operations include addition, bitwise
/// operations, and left rotation.
///
/// # Arguments
///
/// * `a`, `b`, `c`, `d` - u32 registers used in the operations.
/// * `chunks` - A slice of u32 values representing chunks of data to be
///   processed.
/// * `table` - A slice of u32 values from the precomputed table.
fn round_3(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    chunks: &[u32],
    table: &[u32],
) -> (u32, u32, u32, u32) {
    // Let [abcd k s i] denote the operation
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)

    round_op!(a, b, c, d, h, chunks[5], table[33], 4);
    round_op!(d, a, b, c, h, chunks[8], table[34], 11);
    round_op!(c, d, a, b, h, chunks[11], table[35], 16);
    round_op!(b, c, d, a, h, chunks[14], table[36], 23);

    round_op!(a, b, c, d, h, chunks[1], table[37], 4);
    round_op!(d, a, b, c, h, chunks[4], table[38], 11);
    round_op!(c, d, a, b, h, chunks[7], table[39], 16);
    round_op!(b, c, d, a, h, chunks[10], table[40], 23);

    round_op!(a, b, c, d, h, chunks[13], table[41], 4);
    round_op!(d, a, b, c, h, chunks[0], table[42], 11);
    round_op!(c, d, a, b, h, chunks[3], table[43], 16);
    round_op!(b, c, d, a, h, chunks[6], table[44], 23);

    round_op!(a, b, c, d, h, chunks[9], table[45], 4);
    round_op!(d, a, b, c, h, chunks[12], table[46], 11);
    round_op!(c, d, a, b, h, chunks[15], table[47], 16);
    round_op!(b, c, d, a, h, chunks[2], table[48], 23);

    (a, b, c, d)
}

/// Performs the fourth round of the MD5 algorithm.
///
/// This function takes four u32 values, a slice of u32 chunks, and a slice of
/// u32 table values. It performs a series of operations defined by the MD5
/// algorithm for the first round. The operations include addition, bitwise
/// operations, and left rotation.
///
/// # Arguments
///
/// * `a`, `b`, `c`, `d` - u32 registers used in the operations.
/// * `chunks` - A slice of u32 values representing chunks of data to be
///   processed.
/// * `table` - A slice of u32 values from the precomputed table.
fn round_4(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    chunks: &[u32],
    table: &[u32],
) -> (u32, u32, u32, u32) {
    // Let [abcd k s i] denote the operation
    // a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)

    round_op!(a, b, c, d, i, chunks[0], table[49], 6);
    round_op!(d, a, b, c, i, chunks[7], table[50], 10);
    round_op!(c, d, a, b, i, chunks[14], table[51], 15);
    round_op!(b, c, d, a, i, chunks[5], table[52], 21);

    round_op!(a, b, c, d, i, chunks[12], table[53], 6);
    round_op!(d, a, b, c, i, chunks[3], table[54], 10);
    round_op!(c, d, a, b, i, chunks[10], table[55], 15);
    round_op!(b, c, d, a, i, chunks[1], table[56], 21);

    round_op!(a, b, c, d, i, chunks[8], table[57], 6);
    round_op!(d, a, b, c, i, chunks[15], table[58], 10);
    round_op!(c, d, a, b, i, chunks[6], table[59], 15);
    round_op!(b, c, d, a, i, chunks[13], table[60], 21);

    round_op!(a, b, c, d, i, chunks[4], table[61], 6);
    round_op!(d, a, b, c, i, chunks[11], table[62], 10);
    round_op!(c, d, a, b, i, chunks[2], table[63], 15);
    round_op!(b, c, d, a, i, chunks[9], table[64], 21);

    (a, b, c, d)
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn f(x: u32, y: u32, z: u32) -> u32 {
    x & y | !x & z
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn g(x: u32, y: u32, z: u32) -> u32 {
    x & z | y & !z
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_input() {
        let input = "hello";
        let padded = pad_input(input);
        assert_eq!(padded.len() % 64, 0);
    }

    #[test]
    fn test_bytes_to_u32_chunks() {
        let input: Vec<u8> = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let output = bytes_to_u32_chunks(&input);
        assert_eq!(output, vec![0x04030201, 0x08070605]);
    }

    #[test]
    fn test_hash_empty() {
        let text = "";
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0xd41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn test_hash_a() {
        let text = "a";
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0x0cc175b9c0f1b6a831c399e269772661"
        );
    }

    #[test]
    fn test_hash_abc() {
        let text = "abc";
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0x900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn test_hash_long() {
        let text =
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0x57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn test_hash_longer() {
        let text = "Hello everyone, I am learning crypto by learning resources online but also in \
                    books. Here is my implementation of the MD5 algorithm. And here is some \
                    gibberish to verify that it works as expected! \
                    aoirsetnariosetjazutzunuzntarsnt iarntuarntiezfnfp ulnt iearn132 424 23 \
                    zustnu&lj'è çé_ è'çéj'çé_è rsietn _çéè'çé_' uzj'ç_éèj rs nt_çéè'én";
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0xc060ab56adf028acdc4d1f3a2e71c553"
        );
    }

    #[test]
    fn test_hash_english_1000() {
        let text = include_str!("../../datasets/english_1000.txt");
        let md5 = MD5 {};
        assert_eq!(
            md5.hash(text).unwrap(),
            "0xa2dc64d380902d8892ca94e8a8df5d98"
        );
    }
}
