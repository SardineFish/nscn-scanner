use std::fmt::{Debug, Display};

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