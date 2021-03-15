use std::fmt::{self, Debug, Display};

use mongodb::bson;

pub struct ErrorMsg{
    pub msg: String,
}

impl<T> From<T> for ErrorMsg where T : Display {
    fn from(err: T) -> Self {
        Self {
            msg: format!("{}", err),
        }
    }
}

impl Debug for ErrorMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}