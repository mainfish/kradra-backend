#![allow(async_fn_in_trait)]

use super::{
    errors::AuthError,
    types::{AuthUser, Role},
};

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct CreatedUserRecord {
    pub id: String,
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    pub id: String,
    pub user_id: String,
    pub is_revoked: bool,
    pub is_replaced: bool,
    pub expires_unix: i64,
}

pub trait UserRepo: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError>;
    async fn find_by_id(&self, user_id: &str) -> Result<Option<UserRecord>, AuthError>;

    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<CreatedUserRecord, AuthError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> Result<String, AuthError>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError>;
}

pub trait AccessTokenIssuer: Send + Sync {
    fn issue_access(&self, user_id: &str, username: &str, role: Role) -> Result<String, AuthError>;
}

/// Verifies an access token and returns the authenticated user (derived from claims).
pub trait AccessTokenVerifier: Send + Sync {
    fn verify(&self, token: &str) -> Result<AuthUser, AuthError>;
}

pub trait RefreshTokenService: Send + Sync {
    fn generate(&self) -> (String, String); // (plain, hash)
    fn hash(&self, plain: &str) -> String;
}

pub trait RefreshTokenStore: Send + Sync {
    async fn insert_refresh_returning_id(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_unix: i64,
    ) -> Result<String, AuthError>;

    async fn get_by_hash(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>, AuthError>;

    async fn revoke_all_active_for_user(&self, user_id: &str) -> Result<(), AuthError>;

    async fn revoke_and_link(&self, old_id: &str, new_id: &str) -> Result<(), AuthError>;

    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), AuthError>;
}
