use std::fmt::{self, Debug, Display};


macro_rules! impl_error_log {
    () => {
        #[allow(unused_must_use)]
        fn log_consume(self, level: log::Level, target: &str) {
            self.log(level, target);
        }
        fn log_error(self: Self, target: &str) -> Self {
            self.log(log::Level::Error, target)
        }
        #[allow(unused_must_use)]
        fn log_error_consume(self, target: &str) {
            self.log_error(target);
        }
        fn log_warn(self, target: &str) -> Self {
            self.log(log::Level::Warn, target)
        }
        #[allow(unused_must_use)]
        fn log_warn_consume(self, target: &str) {
            self.log_warn(target);
        }
        fn log_info(self, target: &str) -> Self {
            self.log(log::Level::Info, target)
        }
        #[allow(unused_must_use)]
        fn log_info_consume(self, target: &str) {
            self.log_info(target);
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
    fn log(self, level: log::Level, target: &str) -> Self {
        match &self {
            Err(err) => log::log!(target: target, level, "{}", err.msg),
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
    fn log(self, level: log::Level, target: &str) -> Self;
    fn log_consume(self, level: log::Level, target: &str);
    fn log_error(self: Self, target: &str) -> Self;
    fn log_error_consume(self, target: &str);
    fn log_warn(self, target: &str) -> Self;
    fn log_warn_consume(self, target: &str);
    fn log_info(self, target: &str) -> Self;
    fn log_info_consume(self, target: &str);
}

impl<T, E> LogError for Result<T, E> where E: Display {
    fn log(self, level: log::Level, target: &str) -> Self {
        match &self {
            Err(err) => log::log!(target: target, level, "{}", err),
            _ => (),
        }
        self
    }
    impl_error_log!();
}