use actix_web::{HttpRequest, HttpResponse, Responder, http::StatusCode};
use serde::Serialize;

use crate::error::{ApiError};

pub struct Response<T>(pub T);

impl<T> From<T> for Response<T> {
    fn from(response: T) -> Self {
        Self(response)
    }
}

impl<T> Responder for Response<T> where T: Serialize {
    fn respond_to(self, _: &HttpRequest) -> HttpResponse {
        HttpResponse::build(StatusCode::OK).json(self.0)
    }
}

pub type ApiResult<T> = std::result::Result<Response<T>, ApiError>;