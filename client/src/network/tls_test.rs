use super::*;

#[test]
fn test_tls_verifier_creation() {
    let result = TlsVerifier::new(false);
    assert!(result.is_ok());
}

#[test]
fn test_tls_verifier_with_verification() {
    let result = TlsVerifier::new(true);
    assert!(result.is_ok());
}

#[test]
fn test_create_tls_config_for_https() {
    let config = ClientConfig::default();
    let result = create_tls_config(&config);
    assert!(result.is_ok());
}

#[test]
fn test_create_tls_config_for_http() {
    let config = ClientConfig::default();
    let result = create_tls_config(&config);
    assert!(result.is_ok());
}
