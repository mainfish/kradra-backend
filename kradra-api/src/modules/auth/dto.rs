use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug, Clone)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct RegisterUser {
    pub id: String,
    pub username: String,
    pub role: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct RegisterResponse {
    pub user: RegisterUser,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct LoginResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RefreshRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct RefreshResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Deserialize, Debug, Clone)]
pub struct LogoutRequest {
    #[serde(default)]
    pub refresh_token: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LogoutResponse {}
