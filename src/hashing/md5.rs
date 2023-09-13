use crate::hashing::Hasher;

use anyhow::Result;

pub struct MD5 {}

impl Hasher for MD5 {
    fn hash(&self, text: &str) -> Result<String> {
        let table = build_value_table();
        let a: u32 = 0x67452301;
        let b: u32 = 0xEFCDAB89;
        let c: u32 = 0x98BADCFE;
        let d: u32 = 0x98BADCFE;

        let padded_text = pad_input(text);

        todo!()
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

    // Add a '1' just after the input, i.e 1000000
    bytes.push(2 ^ 7);

    // Add 8 bits until the size in bits modulo 512 is 448
    while (bytes.len() * 8 % 512) != 448 {
        bytes.push(0);
    }

    // Compute the size in bits of the input and store the resulting u64
    // as an array of u8
    let size_in_bits = text.len() as u64;
    bytes.extend(u64_to_array_u8(size_in_bits));

    bytes
}

/// Converts a u64 into an array of u8.
///
/// This function takes a u64 as input and converts it into an array of 8 u8s.
/// It does this by shifting the input to the right by a certain number of bits
/// and then performing a bitwise AND operation with 0xFF to keep only the
/// rightmost byte. The result is then cast to u8 and stored in the byte array.
/// # Arguments
/// * `size` - A u64 that will be converted into an array of u8.
/// # Returns
/// * An array of 8 u8s representing the input u64.
fn u64_to_array_u8(size: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8];

    for i in 0..8 {
        // Shift the size to the right by 56 - i * 8 bits, effectively moving the byte
        // we are interested in to the rightmost position. Then we use the
        // bitwise AND operation with 0xFF (which is 11111111 in binary) to keep only
        // the rightmost byte Finally, we cast the result to u8 and store it in
        // the byte array
        bytes[i] = ((size >> (56 - i * 8)) & 0xFF) as u8;
    }

    // Return the byte array
    bytes
}

/// Converts a chunk of u8 values into a vector of u32 values.
///
/// This function takes a mutable reference to a slice of u8 values and converts
/// them into a vector of u32 values. It does this by iterating over the slice
/// and grouping every 4 u8 values into a u32 value. The u32 value is
/// constructed using the from_ne_bytes function, which interprets the u8 values
/// as a native endian integer.
///
/// # Arguments
///
/// * `chunk` - A mutable reference to a slice of u8 values.
///
/// # Returns
///
/// * A vector of u32 values.
fn u8_chunk_to_u32(chunk: &[u8]) -> Vec<u32> {
    // Initialize an empty vector to hold the u32 values
    let mut u32_values: Vec<u32> = Vec::new();

    for chunk in chunk.chunks(4) {
        let u32_value = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        u32_values.push(u32_value);
    }

    // Return the vector of u32 values
    u32_values
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & !z)
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

/// Auxiliary function used in the MD5 algorithm.
/// This function performs a bitwise operation on the input parameters.
fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | z)
}
