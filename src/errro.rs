use serde::Serialize;
use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, reply::Response, Rejection, Reply};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("User not found")]
    WrongCredentialsError,
    #[error("JWT token creation error")]
    JWTTokenCreationError,
    #[error("JWT token error")]
    JWTTokenError,
    #[error("No authorization header")]
    NoAuthHeaderError,
    #[error("Invalid authorization header")]
    InvalidAuthHeaderError,
    #[error("No permission")]
    NoPermissionError,
}


struct ErrorResponse {
    message: String,
    status: String,
}

impl warp::reject::Reject for Error {}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let (code, messaage) = if err.is_not_found() {
        (StatusCode::Not_FOUND, " Not Found".to_string())
    } else if let Some(e) = err.find::<Error>() {
        todo!()
    }
}
