use std::fmt::{Display, Formatter};

use actix_web::{Responder, ResponseError, http::StatusCode};
use nscn::error::SimpleError;

use super::responder::Response;

#[derive(Debug)]
pub enum ServiceError {
    InternalErr(String),
    DataNotFound,
}

// impl From<SimpleError> for ServiceError {
//     fn from(err: SimpleError) -> Self {
//         Self::InternalErr(err.msg)
//     }
// }

impl<T> From<T> for ServiceError where T: Display {
    fn from(err: T) -> Self {
        Self::InternalErr(format!("{}", err))
    }
}

// impl ResponseError for ServiceError {
//     fn status_code(&self) -> StatusCode {
//         StatusCode::INTERNAL_SERVER_ERROR
//     }
// }

// impl Display for ServiceError {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         write!(f, "internal service error")
//     }
// }

#[derive(Debug)]
pub struct ApiError(pub StatusCode, pub String);

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "internal service error")
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.0
    }
}

impl From<ServiceError> for ApiError {
    fn from(err: ServiceError) -> Self {
        match err {
            ServiceError::DataNotFound => Self(StatusCode::NOT_FOUND, "Not found".to_owned()),
            ServiceError::InternalErr(_) => Self(StatusCode::INTERNAL_SERVER_ERROR, "Internal error".to_owned()),
        }
    }
}