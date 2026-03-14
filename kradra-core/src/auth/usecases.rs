use super::{
    errors::AuthError,
    models::{AuthTokens, AuthUser},
    ports::{AccessTokenCodec, PasswordHasher, RefreshTokenCodec, RefreshTokenStore, UserRepo},
};

pub async fn register(
    user_repo: &impl UserRepo,
    password_hasher: &impl PasswordHasher,
    username: &str,
    password: &str,
) -> Result<AuthUser, AuthError> {
    let username = username.trim();

    if username.is_empty() {
        return Err(AuthError::BadRequest("username is required".to_string()));
    }
    if password.len() < 8 {
        return Err(AuthError::BadRequest(
            "password must be at least 8 characters".to_string(),
        ));
    }

    let password_hash = password_hasher.hash(password)?;
    user_repo.create_user(username, &password_hash).await
}

pub async fn login(
    user_repo: &impl UserRepo,
    password_hasher: &impl PasswordHasher,
    token_issuer: &impl AccessTokenCodec,
    refresh_service: &impl RefreshTokenCodec,
    refresh_store: &impl RefreshTokenStore,
    username: &str,
    password: &str,
    client_ip: &str,
    user_agent: Option<String>,
    access_ttl_seconds: i64,
    refresh_ttl_days: i64,
) -> Result<AuthTokens, AuthError> {
    let username = username.trim();
    if username.is_empty() {
        return Err(AuthError::InvalidCredentials);
    }

    let user = user_repo.find_by_username(username).await?;
    if !user.is_active {
        return Err(AuthError::Forbidden);
    }

    let ok = password_hasher.verify(password, &user.password_hash)?;
    if !ok {
        return Err(AuthError::InvalidCredentials);
    }

    let access_token = token_issuer.generate(&user.id, &user.username, user.role.clone())?;
    let (refresh_plain, refresh_hash) = refresh_service.generate();
    let now_unix = unix_now();
    let expires_unix = now_unix + refresh_ttl_days * 24 * 60 * 60;
    let _ = refresh_store
        .insert_refresh_returning_id(
            &user.id,
            &refresh_hash,
            expires_unix,
            client_ip,
            user_agent.as_deref(),
        )
        .await?;

    Ok(AuthTokens {
        access_token,
        refresh_token: refresh_plain,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_seconds,
    })
}

pub async fn refresh(
    user_repo: &impl UserRepo,
    token_issuer: &impl AccessTokenCodec,
    refresh_service: &impl RefreshTokenCodec,
    refresh_store: &impl RefreshTokenStore,
    refresh_token_plain: &str,
    client_ip: &str,
    user_agent: Option<String>,
    access_ttl_seconds: i64,
    refresh_ttl_days: i64,
) -> Result<AuthTokens, AuthError> {
    let refresh_token_plain = refresh_token_plain.trim();
    if refresh_token_plain.is_empty() {
        return Err(AuthError::Unauthorized);
    }

    let old_hash = refresh_service.hash(refresh_token_plain);

    let rec = refresh_store
        .get_by_hash(&old_hash)
        .await
        .map_err(|err| match err {
            AuthError::UserNotFound => AuthError::Unauthorized,
            other => other,
        })?;

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

    let user = user_repo.find_by_id(&rec.user_id).await?;
    if !user.is_active {
        return Err(AuthError::Forbidden);
    }

    // rotation
    let (new_refresh_plain, new_refresh_hash) = refresh_service.generate();
    let new_expires_unix = now_unix + refresh_ttl_days * 24 * 60 * 60;

    refresh_store
        .rotate_refresh_token(
            &old_hash,
            &new_refresh_hash,
            new_expires_unix,
            client_ip,
            user_agent.as_deref(),
        )
        .await?;

    let access_token = token_issuer.generate(&user.id, &user.username, user.role.clone())?;

    Ok(AuthTokens {
        access_token,
        refresh_token: new_refresh_plain,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl_seconds,
    })
}

pub async fn logout(
    refresh_service: &impl RefreshTokenCodec,
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
