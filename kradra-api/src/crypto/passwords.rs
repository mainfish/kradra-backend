use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand_core::OsRng;

/// Хэширует пароль Argon2id и возвращает PHC-строку (её и храним в БД).
pub fn hash_password(password: &str) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default(); // default = Argon2id

    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Проверяет пароль против сохранённой PHC-строки.
pub fn verify_password(
    password: &str,
    password_hash_phc: &str,
) -> Result<bool, password_hash::Error> {
    let parsed = PasswordHash::new(password_hash_phc)?;
    let argon2 = Argon2::default();

    Ok(argon2.verify_password(password.as_bytes(), &parsed).is_ok())
}
