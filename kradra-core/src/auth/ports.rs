#![allow(async_fn_in_trait)]
use super::{
    errors::AuthError,
    models::{AuthUser, RefreshTokenRecord, Role, User},
};

pub trait UserRepo: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<User, AuthError>;
    async fn find_by_id(&self, user_id: &str) -> Result<User, AuthError>;

    async fn create_user(&self, username: &str, password_hash: &str)
    -> Result<AuthUser, AuthError>;
}

pub trait PasswordHasher: Send + Sync {
    fn hash(&self, password: &str) -> Result<String, AuthError>;
    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError>;
}

pub trait AccessTokenCodec: Send + Sync {
    fn generate(&self, user_id: &str, username: &str, role: Role) -> Result<String, AuthError>;
    fn verify(&self, token: &str) -> Result<AuthUser, AuthError>;
}

pub trait RefreshTokenCodec: Send + Sync {
    fn generate(&self) -> (String, String); // (plain, hash)
    fn hash(&self, refresh_token_plain: &str) -> String;
}

pub trait RefreshTokenStore: Send + Sync {
    async fn get_by_hash(&self, token_hash: &str) -> Result<RefreshTokenRecord, AuthError>;

    async fn insert_refresh_returning_id(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_unix: i64,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<String, AuthError>;

    async fn rotate_refresh_token(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        expires_unix: i64,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<RefreshTokenRecord, AuthError>;

    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), AuthError>;
    async fn revoke_all_active_for_user(&self, user_id: &str) -> Result<(), AuthError>;
}
