use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct Pkcs7PaddingError {
    details: String,
}

impl Pkcs7PaddingError {
    pub fn new(msg: &str) -> Self {
        Self {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for Pkcs7PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for Pkcs7PaddingError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl PartialEq for Pkcs7PaddingError {
    fn eq(&self, other: &Self) -> bool {
        self.details == other.details
    }
}
