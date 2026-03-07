use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{EncodingKey, Header, encode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize)]
pub struct AccessClaims {
    pub sub: String, // user id (uuid as text)
    pub username: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as i64
}

pub fn make_access_token(
    user_id: &str,
    username: &str,
    role: &str,
    jwt_secret: &str,
    ttl_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = unix_now();
    let exp = now + ttl_seconds.max(1);

    let claims = AccessClaims {
        sub: user_id.to_string(),
        username: username.to_string(),
        role: role.to_string(),
        iat: now as usize,
        exp: exp as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
}

/// Returns (refresh_plain, refresh_hash_for_db)
pub fn make_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let refresh_plain = URL_SAFE_NO_PAD.encode(bytes);

    let mut hasher = Sha256::new();
    hasher.update(refresh_plain.as_bytes());
    let refresh_hash = URL_SAFE_NO_PAD.encode(hasher.finalize());

    (refresh_plain, refresh_hash)
}
