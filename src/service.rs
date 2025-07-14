use crate::{DpAuthSessionError, DpAuthSessionPayload};
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine as _};

/// Service for managing session tokens using custom encrypted format
pub struct DpAuthSessionService;

impl DpAuthSessionService {
  /// Default token expiration time (3 days in seconds)
  const DEFAULT_EXPIRATION_SECONDS: i64 = 3 * 24 * 60 * 60;

  /// Encode a session payload into an encrypted token.
  ///
  /// This method takes a session payload containing user information and creates
  /// an encrypted token that can be safely transmitted and stored. The token uses
  /// AES-256-GCM encryption with a random nonce for security.
  ///
  /// # Arguments
  ///
  /// * `payload` - The session payload containing user ID and timestamps
  /// * `secret` - The 32-byte secret key for AES-256-GCM encryption
  ///
  /// # Returns
  ///
  /// Returns a base64-encoded encrypted token string on success, or a `DpAuthSessionError` on failure.
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// - JSON serialization fails (`JsonError`)
  /// - Encryption fails (`EncodingError`)
  ///
  /// # Examples
  ///
  /// ```rust
  /// use dp_auth_session_service::{DpAuthSessionService, DpAuthSessionPayload};
  ///
  /// // Use a 32-byte secret key
  /// let secret = &[0u8; 32]; // In practice, use a proper secret
  /// let payload = DpAuthSessionService::create_payload(123);
  /// let token = DpAuthSessionService::encode_token(&payload, secret)?;
  /// println!("Generated token: {}", token);
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn encode_token(
    payload: &DpAuthSessionPayload,
    secret: &[u8],
  ) -> Result<String, DpAuthSessionError> {
    let key = Key::<Aes256Gcm>::from_slice(secret);
    let cipher = Aes256Gcm::new(key);

    // Serialize payload to JSON
    let json_data =
      serde_json::to_vec(payload).map_err(|e| DpAuthSessionError::JsonError(e.to_string()))?;

    // Generate a random nonce
    let nonce = Aes256Gcm::generate_nonce(&mut rand::rngs::OsRng);

    // Encrypt the JSON data
    let mut buffer = json_data;
    cipher
      .encrypt_in_place(&nonce, b"", &mut buffer)
      .map_err(|e| DpAuthSessionError::EncodingError(e.to_string()))?;

    // Combine nonce + encrypted data
    let mut result = nonce.to_vec();
    result.extend_from_slice(&buffer);

    // Base64 encode the result
    Ok(general_purpose::STANDARD.encode(result))
  }

  /// Decode an encrypted token and retrieve the session payload.
  ///
  /// This method takes an encrypted token string and decrypts it to retrieve
  /// the original session payload. It also validates that the token has not expired.
  ///
  /// # Arguments
  ///
  /// * `token` - The base64-encoded encrypted token string
  /// * `secret` - The 32-byte secret key for AES-256-GCM decryption
  ///
  /// # Returns
  ///
  /// Returns the decrypted session payload on success, or a `DpAuthSessionError` on failure.
  ///
  /// # Errors
  ///
  /// This function will return an error if:
  /// - The token format is invalid (`InvalidToken`)
  /// - Decryption fails (`DecodingError`)
  /// - JSON deserialization fails (`JsonError`)
  /// - The token has expired (`TokenExpired`)
  ///
  /// # Examples
  ///
  /// ```rust
  /// use dp_auth_session_service::{DpAuthSessionService, DpAuthSessionPayload};
  ///
  /// // Use a 32-byte secret key
  /// let secret = &[0u8; 32]; // In practice, use a proper secret
  ///
  /// // Create and encode a token first
  /// let payload = DpAuthSessionService::create_payload(123);
  /// let token = DpAuthSessionService::encode_token(&payload, secret)?;
  ///
  /// // Then decode it
  /// match DpAuthSessionService::decode_token(&token, secret) {
  ///     Ok(decoded_payload) => println!("User ID: {}", decoded_payload.sub),
  ///     Err(e) => println!("Token validation failed: {}", e),
  /// }
  /// # Ok::<(), Box<dyn std::error::Error>>(())
  /// ```
  pub fn decode_token(
    token: &str,
    secret: &[u8],
  ) -> Result<DpAuthSessionPayload, DpAuthSessionError> {
    let key = Key::<Aes256Gcm>::from_slice(secret);
    let cipher = Aes256Gcm::new(key);

    // Base64 decode the token
    let encrypted_data = general_purpose::STANDARD
      .decode(token)
      .map_err(|e| DpAuthSessionError::InvalidToken(format!("Base64 decode error: {e}")))?;

    // Check minimum length (nonce + some encrypted data)
    if encrypted_data.len() < 12 {
      return Err(DpAuthSessionError::InvalidToken(
        "Token too short".to_string(),
      ));
    }

    // Split nonce and encrypted payload
    let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt the data
    let mut buffer = ciphertext.to_vec();
    cipher
      .decrypt_in_place(nonce, b"", &mut buffer)
      .map_err(|e| DpAuthSessionError::DecodingError(format!("Decryption failed: {e}")))?;

    // Deserialize JSON to payload
    let payload: DpAuthSessionPayload =
      serde_json::from_slice(&buffer).map_err(|e| DpAuthSessionError::JsonError(e.to_string()))?;

    // Check if token has expired
    let current_time = chrono::Utc::now().timestamp();
    if payload.exp < current_time {
      return Err(DpAuthSessionError::TokenExpired);
    }

    Ok(payload)
  }

  /// Create a new session payload for a user.
  ///
  /// This method creates a new session payload with the current timestamp as the
  /// issued time and sets the expiration to 3 days from now.
  ///
  /// # Arguments
  ///
  /// * `user_id` - The unique identifier of the user for this session
  ///
  /// # Returns
  ///
  /// Returns a new `DpAuthSessionPayload` with the user ID and appropriate timestamps.
  ///
  /// # Examples
  ///
  /// ```rust
  /// use dp_auth_session_service::DpAuthSessionService;
  ///
  /// let payload = DpAuthSessionService::create_payload(123);
  /// assert_eq!(payload.sub, 123);
  /// assert!(payload.exp > payload.iat);
  /// ```
  pub fn create_payload(user_id: i64) -> DpAuthSessionPayload {
    let current_time = chrono::Utc::now().timestamp();

    DpAuthSessionPayload {
      sub: user_id,
      iat: current_time,
      exp: current_time + Self::DEFAULT_EXPIRATION_SECONDS,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  // Test secret - 32 bytes for AES-256 (base64-decoded from QvQlwpMujK+qzdRbUCikjc131OKt1KHE38Yq37V0Tbg=)
  const TEST_SECRET: &[u8] = &[
    0x42, 0xf4, 0x25, 0xc2, 0x93, 0x2e, 0x8c, 0xaf, 0xaa, 0xcd, 0xd4, 0x5b, 0x50, 0x28, 0xa4, 0x8d,
    0xcd, 0x74, 0xd4, 0xe2, 0xad, 0xd4, 0xa1, 0xc4, 0xdf, 0xc6, 0x2a, 0xdf, 0xb5, 0x74, 0x4d, 0xb8,
  ];

  #[test]
  fn test_create_payload() {
    let user_id = 123;
    let payload = DpAuthSessionService::create_payload(user_id);

    assert_eq!(payload.sub, user_id);
    assert!(payload.iat > 0);
    assert_eq!(
      payload.exp,
      payload.iat + 3 * 24 * 60 * 60 // 3 days in seconds
    );
  }

  #[test]
  fn test_encode_decode_roundtrip() {
    let payload = DpAuthSessionService::create_payload(456);
    let token = DpAuthSessionService::encode_token(&payload, TEST_SECRET).unwrap();
    let decoded_payload = DpAuthSessionService::decode_token(&token, TEST_SECRET).unwrap();

    assert_eq!(payload, decoded_payload);
  }

  #[test]
  fn test_decode_expired_token() {
    // Create payload with past expiration
    let expired_payload = DpAuthSessionPayload {
      sub: 789,
      iat: chrono::Utc::now().timestamp() - 3600, // 1 hour ago
      exp: chrono::Utc::now().timestamp() - 1800, // 30 minutes ago (expired)
    };

    let token = DpAuthSessionService::encode_token(&expired_payload, TEST_SECRET).unwrap();
    let result = DpAuthSessionService::decode_token(&token, TEST_SECRET);

    assert!(matches!(result, Err(DpAuthSessionError::TokenExpired)));
  }

  #[test]
  fn test_decode_invalid_token() {
    // Test empty token
    let result = DpAuthSessionService::decode_token("", TEST_SECRET);
    assert!(matches!(result, Err(DpAuthSessionError::InvalidToken(_))));

    // Test invalid base64
    let result = DpAuthSessionService::decode_token("invalid-base64!", TEST_SECRET);
    assert!(matches!(result, Err(DpAuthSessionError::InvalidToken(_))));

    // Test too short token
    let result = DpAuthSessionService::decode_token("dGVzdA==", TEST_SECRET); // "test" in base64 (too short)
    assert!(matches!(result, Err(DpAuthSessionError::InvalidToken(_))));
  }

  #[test]
  fn test_encode_decode_with_different_secrets() {
    let payload = DpAuthSessionService::create_payload(123);

    // Encode with one secret
    let token = DpAuthSessionService::encode_token(&payload, TEST_SECRET).unwrap();

    // Try to decode with different secret
    let different_secret = &[0u8; 32]; // All zeros
    let result = DpAuthSessionService::decode_token(&token, different_secret);

    assert!(matches!(result, Err(DpAuthSessionError::DecodingError(_))));
  }

  #[test]
  fn test_multiple_users_different_tokens() {
    let payload1 = DpAuthSessionService::create_payload(100);
    let payload2 = DpAuthSessionService::create_payload(200);

    let token1 = DpAuthSessionService::encode_token(&payload1, TEST_SECRET).unwrap();
    let token2 = DpAuthSessionService::encode_token(&payload2, TEST_SECRET).unwrap();

    // Tokens should be different
    assert_ne!(token1, token2);

    // Each token should decode to its original payload
    let decoded1 = DpAuthSessionService::decode_token(&token1, TEST_SECRET).unwrap();
    let decoded2 = DpAuthSessionService::decode_token(&token2, TEST_SECRET).unwrap();

    assert_eq!(payload1, decoded1);
    assert_eq!(payload2, decoded2);
  }

  #[test]
  fn test_token_uniqueness_same_user() {
    let user_id = 123;

    // Create two payloads for the same user (different timestamps)
    let payload1 = DpAuthSessionService::create_payload(user_id);
    std::thread::sleep(std::time::Duration::from_millis(10)); // Ensure different timestamp
    let payload2 = DpAuthSessionService::create_payload(user_id);

    let token1 = DpAuthSessionService::encode_token(&payload1, TEST_SECRET).unwrap();
    let token2 = DpAuthSessionService::encode_token(&payload2, TEST_SECRET).unwrap();

    // Tokens should be different even for same user due to different timestamps and nonces
    assert_ne!(token1, token2);
  }

  #[test]
  fn test_error_display() {
    let encoding_error = DpAuthSessionError::EncodingError("test error".to_string());
    assert!(encoding_error
      .to_string()
      .contains("Token encoding error: test error"));

    let decoding_error = DpAuthSessionError::DecodingError("test error".to_string());
    assert!(decoding_error
      .to_string()
      .contains("Token decoding error: test error"));

    let expired_error = DpAuthSessionError::TokenExpired;
    assert_eq!(expired_error.to_string(), "Token has expired");

    let invalid_error = DpAuthSessionError::InvalidToken("test error".to_string());
    assert!(invalid_error
      .to_string()
      .contains("Invalid token: test error"));

    let json_error = DpAuthSessionError::JsonError("test error".to_string());
    assert!(json_error.to_string().contains("JSON error: test error"));
  }

  #[test]
  fn test_payload_serialization() {
    let payload = DpAuthSessionPayload {
      sub: 123,
      iat: 1706356800,
      exp: 1706616000,
    };

    // Test JSON serialization
    let json = serde_json::to_string(&payload).unwrap();
    let deserialized: DpAuthSessionPayload = serde_json::from_str(&json).unwrap();

    assert_eq!(payload, deserialized);
  }

  #[test]
  fn test_large_user_id() {
    let large_user_id = i64::MAX;
    let payload = DpAuthSessionService::create_payload(large_user_id);

    let token = DpAuthSessionService::encode_token(&payload, TEST_SECRET).unwrap();
    let decoded = DpAuthSessionService::decode_token(&token, TEST_SECRET).unwrap();

    assert_eq!(payload.sub, large_user_id);
    assert_eq!(decoded.sub, large_user_id);
  }
}
