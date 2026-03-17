#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}
