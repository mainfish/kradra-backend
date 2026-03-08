use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::ports::{AccessTokenIssuer, AccessTokenVerifier, RefreshTokenService};
use kradra_core::auth::types::{AuthUser, Role};

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_secs() as i64
}

/// JWT claims DTO used only at the boundary (jsonwebtoken requires serde).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtAccessClaims {
    sub: String,
    username: String,
    role: String,
    exp: usize,
    iat: usize,
}

#[derive(Clone)]
pub struct JwtIssuer {
    pub jwt_secret: String,
    pub access_ttl_seconds: i64,
}

impl AccessTokenIssuer for JwtIssuer {
    fn issue_access(&self, user_id: &str, username: &str, role: Role) -> Result<String, AuthError> {
        let now = unix_now();
        let exp = now + self.access_ttl_seconds.max(1);

        let claims = JwtAccessClaims {
            sub: user_id.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            iat: now as usize,
            exp: exp as usize,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
        .map_err(|_| AuthError::Internal)
    }
}

#[derive(Clone)]
pub struct JwtAccessVerifier {
    pub jwt_secret: String,
}

impl AccessTokenVerifier for JwtAccessVerifier {
    fn verify(&self, token: &str) -> Result<AuthUser, AuthError> {
        let claims =
            decode_access_claims(token, &self.jwt_secret).map_err(|_| AuthError::Unauthorized)?;

        let role = Role::try_from(claims.role.as_str()).map_err(|_| AuthError::Unauthorized)?;

        Ok(AuthUser {
            id: claims.sub,
            username: claims.username,
            role,
        })
    }
}

#[derive(Clone, Default)]
pub struct RefreshService;

impl RefreshService {
    pub fn hash_refresh_token(refresh_plain: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(refresh_plain.as_bytes());
        URL_SAFE_NO_PAD.encode(hasher.finalize())
    }
}

impl RefreshTokenService for RefreshService {
    fn generate(&self) -> (String, String) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);

        let refresh_plain = URL_SAFE_NO_PAD.encode(bytes);
        let refresh_hash = Self::hash_refresh_token(&refresh_plain);

        (refresh_plain, refresh_hash)
    }

    fn hash(&self, plain: &str) -> String {
        Self::hash_refresh_token(plain)
    }
}

fn decode_access_claims(
    token: &str,
    jwt_secret: &str,
) -> Result<JwtAccessClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let data = decode::<JwtAccessClaims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )?;

    Ok(data.claims)
}
