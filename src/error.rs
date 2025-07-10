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
        match e {
            Error::WrongCredentialsError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::JWTTokenCreationError => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Error::JWTTokenError => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Error::NoAuthHeaderError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::InvalidAuthHeaderError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::NoPermissionError => (StatusCode::FORBIDDEN, e.to_string()),
        }
    }
    else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed".to_string())
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string())
    };

    let json = warp::reply::json(&ErrorResponse{
        status: code.to_string(),
        message: messaage,
    });

    Ok(warp::reply::with_status(json, code))
    
}
