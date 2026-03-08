use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString},
};
use rand_core::OsRng;

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::ports::PasswordHasher;

#[derive(Clone, Default)]
pub struct Argon2Hasher;

impl PasswordHasher for Argon2Hasher {
    fn hash(&self, password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| AuthError::Internal)?
            .to_string();

        Ok(hash)
    }

    fn verify(&self, password: &str, password_hash: &str) -> Result<bool, AuthError> {
        let parsed = PasswordHash::new(password_hash).map_err(|_| AuthError::Internal)?;
        let argon2 = Argon2::default();

        Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
    }
}
