use std::fmt;

#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials,
    UserAlreadyExists,
    Unauthorized,
    Forbidden,
    TokenInvalid,
    TokenExpired,
    Internal,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidCredentials => write!(f, "invalid credentials"),
            AuthError::UserAlreadyExists => write!(f, "user already exists"),
            AuthError::Unauthorized => write!(f, "unauthorized"),
            AuthError::Forbidden => write!(f, "forbidden"),
            AuthError::TokenInvalid => write!(f, "token invalid"),
            AuthError::TokenExpired => write!(f, "token expired"),
            AuthError::Internal => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for AuthError {}
