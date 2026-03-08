use kradra_core::auth::ports::PasswordHasher;

#[test]
fn hash_and_verify_roundtrip() {
    let password = "test12345";
    let hasher = crate::crypto::passwords::Argon2Hasher::default();

    let phc = hasher.hash(password).unwrap();
    assert!(hasher.verify(password, &phc).unwrap());
    assert!(!hasher.verify("wrong", &phc).unwrap());
}
