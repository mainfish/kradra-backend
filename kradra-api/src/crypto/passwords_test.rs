#[test]
fn hash_and_verify_roundtrip() {
    let password = "test12345";

    let phc = crate::crypto::passwords::hash_password(password).unwrap();
    assert!(crate::crypto::passwords::verify_password(password, &phc).unwrap());
    assert!(!crate::crypto::passwords::verify_password("wrong", &phc).unwrap());
}
