#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub id: String,
    pub user_id: String,
    pub is_revoked: bool,
    pub is_replaced: bool,
    pub expires_unix: i64,
}

#[derive(Debug, Clone)]
pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}
