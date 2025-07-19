use hex;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignatureVerificationError {
    #[error("Invalid hex encoding in signature: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Invalid HMAC key")]
    InvalidKey,

    #[error("Invalid signature format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Verify HMAC-SHA256 signature for webhook payload
///
/// # Arguments
/// * `secret` - The shared secret key
/// * `payload` - The JSON payload as a string
/// * `signature` - The signature header from Discourse (format: "sha256=...")
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(SignatureVerificationError)` if verification fails
pub fn verify_signature(
    secret: &str,
    payload: &str,
    signature: &str,
) -> Result<(), SignatureVerificationError> {
    let signature = signature.strip_prefix("sha256=").ok_or_else(|| {
        SignatureVerificationError::InvalidFormat("Signature must start with 'sha256='".to_string())
    })?;

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| SignatureVerificationError::InvalidKey)?;

    mac.update(payload.as_bytes());

    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    if signature.eq_ignore_ascii_case(&expected_hex) {
        Ok(())
    } else {
        Err(SignatureVerificationError::VerificationFailed)
    }
}

/// Verify HMAC-SHA256 signature for JSON payload
///
/// Convenience function that serializes the JSON value to string first
pub fn verify_json_signature(
    secret: &str,
    payload: &serde_json::Value,
    signature: &str,
) -> Result<(), SignatureVerificationError> {
    let payload_str = serde_json::to_string(payload).map_err(|_| {
        SignatureVerificationError::InvalidFormat("Failed to serialize JSON payload".to_string())
    })?;

    verify_signature(secret, &payload_str, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_signature_verification() {
        let secret = "test_secret";
        let payload = r#"{"test":"data"}"#;

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert!(verify_signature(secret, payload, &signature).is_ok());

        assert!(verify_signature("wrong_secret", payload, &signature).is_err());

        assert!(verify_signature(secret, payload, "invalid_format").is_err());
    }

    #[test]
    fn test_json_signature_verification() {
        let secret = "test_secret";
        let payload = json!({"test": "data"});
        let payload_str = serde_json::to_string(&payload).unwrap();

        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_str.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert!(verify_json_signature(secret, &payload, &signature).is_ok());
    }
}
