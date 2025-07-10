use crate::{error::Error, Result, WebResult};
use chrono::{prelude::*, Duration};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::fmt;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};

const JWT_SECRET: &[u8] = b"secret";
const BEARER: &str = "Bearer ";

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    fn from_str(role: &str) -> Role {
        match role {
            "admin" => Role::Admin,
            "user" => Role::User,
            _ => Role::User, // fallback
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Admin => write!(f, "admin"),
            Role::User => write!(f, "user"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: Role,
    exp: usize,
}

// ✅ 修正: スペルミス
pub fn create_jwt(uid: &str, role: &Role) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_string(),
        role: role.clone(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| Error::JWTTokenCreationError)
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
}

async fn authorize(role: Role, headers: HeaderMap<HeaderValue>) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|_| reject::custom(Error::JWTTokenError))?;

            if decoded.claims.role == role {
                Ok(decoded.claims.sub)
            } else {
                Err(reject::custom(Error::NoPermissionError))
            }
        }
        Err(e) => Err(reject::custom(e)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String> {
    let header = match headers.get(AUTHORIZATION) {
        Some(header) => header,
        None => return Err(Error::NoAuthHeaderError),
    };
    let auth_header = header.to_str().map_err(|_| Error::InvalidAuthHeaderError)?;
    if auth_header.starts_with(BEARER) {
        Ok(auth_header.trim_start_matches(BEARER).to_string())
    } else {
        Err(Error::InvalidAuthHeaderError)
    }
}
