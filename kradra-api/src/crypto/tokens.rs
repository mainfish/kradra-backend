use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
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

/// Decode + validate access JWT (signature + exp)
pub fn decode_access_token(
    token: &str,
    jwt_secret: &str,
) -> Result<AccessClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )?;

    Ok(data.claims)
}

/// Returns (refresh_plain, refresh_hash_for_db)
pub fn make_refresh_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let refresh_plain = URL_SAFE_NO_PAD.encode(bytes);
    let refresh_hash = hash_refresh_token(&refresh_plain);

    (refresh_plain, refresh_hash)
}

/// Hash refresh token for DB storage (base64url(sha256(token)))
pub fn hash_refresh_token(refresh_plain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(refresh_plain.as_bytes());

    URL_SAFE_NO_PAD.encode(hasher.finalize())
}
