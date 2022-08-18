use std::error::Error;
use std::fmt;


#[derive(Debug)]
pub struct HammingDistanceParsingError {
    details: String
}

impl HammingDistanceParsingError {
    pub fn new(msg: &str) -> Self {
        Self{details: msg.to_string()}
    }
}

impl fmt::Display for HammingDistanceParsingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for HammingDistanceParsingError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl PartialEq for HammingDistanceParsingError {
    fn eq(&self, other: &Self) -> bool {
        self.details == other.details
    }
}
