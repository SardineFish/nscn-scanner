use std::fmt::{self, Debug, Display};

use openssl::ssl::HandshakeError;

pub struct SimpleError{
    pub msg: String,
}

impl SimpleError {
    pub fn new(msg: &str) -> Self{
        Self{ 
            msg: msg.to_owned(),
        }
    }
    pub fn from_debug<T: Debug>(err: T) -> Self {
        Self {
            msg: format!("{:?}", err)
        }
    }
}

impl<T> From<T> for SimpleError where T : Display {
    fn from(err: T) -> Self {
        Self {
            msg: format!("{}", err),
        }
    }
}

impl Debug for SimpleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}