use super::{
    errors::AuthError,
    ports::{
        AccessTokenIssuer, CreatedUserRecord, PasswordHasher, RefreshTokenService,
        RefreshTokenStore, UserRepo,
    },
};

#[derive(Debug, Clone)]
pub struct LoginOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub async fn register(
    user_repo: &impl UserRepo,
    password_hasher: &impl PasswordHasher,
    username: &str,
    password: &str,
) -> Result<CreatedUserRecord, AuthError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AuthError::InvalidCredentials);
    }
    if password.len() < 8 {
        return Err(AuthError::InvalidCredentials);
    }

    let password_hash = password_hasher.hash(password)?;
    user_repo.create_user(username, &password_hash).await
}

pub async fn login(
    user_repo: &impl UserRepo,
    password_hasher: &impl PasswordHasher,
    token_issuer: &impl AccessTokenIssuer,
    refresh_service: &impl RefreshTokenService,
    refresh_store: &impl RefreshTokenStore,
    username: &str,
    password: &str,
    access_ttl_seconds: i64,
    refresh_ttl_days: i64,
) -> Result<LoginOutput, AuthError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AuthError::InvalidCredentials);
    }

    let user = user_repo
        .find_by_username(username)
        .await?
        .ok_or(AuthError::InvalidCredentials)?;

    if !user.is_active {
        return Err(AuthError::Unauthorized);
    }

    let ok = password_hasher.verify(password, &user.password_hash)?;
    if !ok {
        return Err(AuthError::InvalidCredentials);
    }

    let access_token = token_issuer.issue_access(&user.id, &user.username, user.role.clone())?;

    let (refresh_plain, refresh_hash) = refresh_service.generate();

    let now_unix = unix_now();
    let refresh_expires_unix = now_unix + refresh_ttl_days * 24 * 60 * 60;

    let _ = refresh_store
        .insert_refresh_returning_id(&user.id, &refresh_hash, refresh_expires_unix)
        .await?;

    Ok(LoginOutput {
        access_token,
        refresh_token: refresh_plain,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_seconds,
    })
}

#[derive(Debug, Clone)]
pub struct RefreshOutput {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub async fn refresh(
    user_repo: &impl UserRepo,
    token_issuer: &impl AccessTokenIssuer,
    refresh_service: &impl RefreshTokenService,
    refresh_store: &impl RefreshTokenStore,
    refresh_token_plain: &str,
    access_ttl_seconds: i64,
    refresh_ttl_days: i64,
) -> Result<RefreshOutput, AuthError> {
    let refresh_token_plain = refresh_token_plain.trim();
    if refresh_token_plain.is_empty() {
        return Err(AuthError::Unauthorized);
    }

    let old_hash = refresh_service.hash(refresh_token_plain);

    let rec = refresh_store
        .get_by_hash(&old_hash)
        .await?
        .ok_or(AuthError::Unauthorized)?;

    let now_unix = unix_now();

    // expired
    if rec.expires_unix <= now_unix {
        return Err(AuthError::Unauthorized);
    }

    // reuse detection
    if rec.is_revoked || rec.is_replaced {
        refresh_store
            .revoke_all_active_for_user(&rec.user_id)
            .await?;
        return Err(AuthError::Unauthorized);
    }

    let user = user_repo
        .find_by_id(&rec.user_id)
        .await?
        .ok_or(AuthError::Unauthorized)?;

    if !user.is_active {
        return Err(AuthError::Unauthorized);
    }

    // rotation
    let (new_refresh_plain, new_refresh_hash) = refresh_service.generate();
    let new_expires_unix = now_unix + refresh_ttl_days * 24 * 60 * 60;

    let new_id = refresh_store
        .insert_refresh_returning_id(&rec.user_id, &new_refresh_hash, new_expires_unix)
        .await?;

    refresh_store.revoke_and_link(&rec.id, &new_id).await?;

    let access_token = token_issuer.issue_access(&user.id, &user.username, user.role.clone())?;

    Ok(RefreshOutput {
        access_token,
        refresh_token: new_refresh_plain,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_seconds,
    })
}

pub async fn logout(
    refresh_service: &impl RefreshTokenService,
    refresh_store: &impl RefreshTokenStore,
    refresh_token_plain: &str,
) -> Result<(), AuthError> {
    let refresh_token_plain = refresh_token_plain.trim();
    if refresh_token_plain.is_empty() {
        return Err(AuthError::Unauthorized);
    }

    let hash = refresh_service.hash(refresh_token_plain);
    refresh_store.revoke_by_hash(&hash).await?;

    Ok(())
}

fn unix_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as i64
}
