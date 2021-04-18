use std::fmt::{Display, Formatter};

use actix_web::{ResponseError, http::StatusCode};
use nscn::error::SimpleError;

use super::responder::Response;

#[derive(Debug)]
pub struct ServiceError {
    msg: String,
}

impl From<SimpleError> for ServiceError {
    fn from(err: SimpleError) -> Self {
        Self {
            msg: err.msg
        }
    }
}

impl ResponseError for ServiceError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "internal service error")
    }
}
