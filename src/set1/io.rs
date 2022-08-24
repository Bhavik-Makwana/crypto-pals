use std::{
    fs,
    fs::File,
    io::{prelude::*, BufReader},
    path::Path,
};

type FileStringVecOutput = Vec<String>;
type FileStringBlockOutput = String;

pub fn lines_from_file(filename: impl AsRef<Path>) -> FileStringVecOutput {
    let file = File::open(filename).expect("no such file");
    let buf = BufReader::new(file);
    buf.lines()
        .map(|l| l.expect("Could not parse line"))
        .collect()
}

pub fn read_file(filename: &str) -> FileStringBlockOutput {
    let mut file = File::open(filename).expect("no such file");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("to work");
    contents
}

pub fn read_file_no_newline(filename: &str) -> String {
    fs::read_to_string(filename)
        .and_then(|res| Ok(res.replace("\n", "")))
        .expect("Error reading file")
}
