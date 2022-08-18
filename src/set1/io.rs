use std::{
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};


pub fn lines_from_file(filename: impl AsRef<Path>) -> Vec<String> {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

pub fn read_file(filename: &str) -> String {
    let mut file = File::open(filename).expect("no such file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("to work");
    contents
}
