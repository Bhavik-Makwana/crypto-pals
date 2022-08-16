pub fn score(c: char) -> i32 {
    let uppercase: String = c.to_uppercase().collect(); 
    match &uppercase[..] {
        "E" => 10,
        "T" => 9,
        "A" | "I" | "N" | "O" | "S" => 8,
        "H" => 7,
        "R" => 6,
        "D" => 5,
        "L" => 4,
        "U" => 3,
        "C" | "M" => 2,
        "F" => 1,
        "W" | "Y" => 1,
        "G" | "P" => 1,
        "B" => 1,
        "V" => 1,
        "K" => 1,
        "Q" => 1,
        "J" | "X" => 1,
        "Z" => 1,
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


