use std::fmt::{self, Debug, Display};

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

impl<T> LogError for Result<T, SimpleError> {
    fn log_error(&self) {
        match self {
            Err(err) => log::error!("{}", err.msg),
            _ => (),
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

pub trait LogError{
    fn log_error(&self);
}

impl<T, E> LogError for Result<T, E> where E: Display {
    fn log_error(&self) {
        match self {
            Err(err) => log::error!("{}", err),
            _ => (),
        }
    }
}
