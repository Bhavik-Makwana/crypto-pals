// very basic -- room for improvement
pub fn score(c: char) -> i32 {
    match c {
        'E' => 10,
        'T' => 9,
        'A' | 'I' | 'N' | 'O' | 'S' => 8,
        'H' => 7,
        'R' => 6,
        'D' => 5,
        'L' => 4,
        'U' => 3,
        'C' | 'M' => 2,
        'F' => 1,
        'W' | 'Y' => 1,
        'G' | 'P' => 1,
        'B' => 1,
        'V' => 1,
        'K' => 1,
        'Q' => 1,
        'J' | 'X' => 1,
        'Z' => 1,
        'e' => 20,
        't' => 19,
        'a' | 'i' | 'n' | 'o' | 's' => 18,
        'h' => 17,
        'r' => 16,
        'd' => 15,
        'l' => 14,
        'u' => 13,
        'c' | 'm' => 12,
        'f' => 11,
        'w' | 'y' => 11,
        'g' | 'p' => 11,
        'b' => 11,
        'v' => 11,
        'k' => 11,
        'q' => 11,
        'j' | 'x' => 11,
        'z' => 11,
        _ => -10,
    }
}

pub fn single_byte_xor(input: &str, key: u8) -> String {
    let decoded = hex::decode(input).unwrap();
    let xor_bytes: Vec<u8> = decoded.iter()
        .map(|&c| c ^ key)
        .collect();

    hex::encode(xor_bytes)
}


