use std::fmt::{self, Debug, Display};


macro_rules! impl_error_log {
    () => {
        fn log_consume(self, level: log::Level) {
            self.log(level);
        }
        fn log_error(self: Self) -> Self {
            self.log(log::Level::Error)
        }
        fn log_error_consume(self) {
            self.log_error();
        }
        fn log_warn(self) -> Self {
            self.log(log::Level::Warn)
        }
        fn log_warn_consume(self) {
            self.log_warn();
        }
        fn log_info(self) -> Self {
            self.log(log::Level::Info)
        }
        fn log_info_consume(self) {
            self.log_info();
        }
    };
}

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
    fn log(self, level: log::Level) -> Self {
        match &self {
            Err(err) => log::log!(level, "{}", err.msg),
            Ok(_) => (),
        }
        self
    }
    impl_error_log!();
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

pub trait LogError {
    fn log(self, level: log::Level) -> Self;
    fn log_consume(self, level: log::Level);
    fn log_error(self: Self) -> Self;
    fn log_error_consume(self);
    fn log_warn(self) -> Self;
    fn log_warn_consume(self);
    fn log_info(self) -> Self;
    fn log_info_consume(self);
}

impl<T, E> LogError for Result<T, E> where E: Display {
    fn log(self, level: log::Level) -> Self {
        match &self {
            Err(err) => log::log!(level, "{}", err),
            _ => (),
        }
        self
    }
    impl_error_log!();
}