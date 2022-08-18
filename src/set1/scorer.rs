use std::collections::HashMap;
// very basic -- room for improvement
// let scoring_values = HashMap::from([
//     ('E', 10),
//     ('T', 9),
//     ('A', 8), ('I', 8), ('N', 8), ('O', 8), ('S', 8),
//     ('H', 7),
//     ('R', 6),
//     ('D', 5),
//     ('L', 4),
//     ('U', 3),
//     ('C', 2), ('M', 2),
//     ('F', 1),
//     ('W', 1), ('Y', 1),
//     ('G', 1), ('P', 1),
//     ('B', 1),
//     ('V', 1),
//     ('K', 1),
//     ('Q', 1),
//     ('J', 1), ('X', 1),
//     ('Z', 1),
//     ('e', 10),
//     ('t', 9),
//     ('a', 8), ('i', 8), ('n', 8), ('o', 8), ('s', 8)
//     ('h', 7),
//     ('r', 6),
//     ('d', 5),
//     ('l', 4),
//     ('u', 3),
//     ('c', 2), ('m', 2),
//     ('f', 1),
//     ('w', 1), ('y', 1),
//     ('g', 1), ('p', 1),
//     ('b', 1),
//     ('v', 1),
//     ('k', 1),
//     ('q', 1),
//     ('j', 1), ('x', 1),
//     ('z', 1),
//     ]);


pub fn score(c: char) -> i32 {

        
    // let res = scoring_values.get(&c);
    // match res {
    //     Some(res) => *res,
    //     None => -10,
    // }
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

pub fn single_byte_xor_mut(input: &str, key: u8) -> String {
    let decoded = hex::decode(input).unwrap();
    
    let xor_bytes: Vec<u8> = decoded.iter()
        .map(|&c| c ^ key)
        .collect();

    hex::encode(xor_bytes)
}


