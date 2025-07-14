use std::fmt;

/// Error types for session token operations
#[derive(Debug)]
pub enum DpAuthSessionError {
  /// Token encoding failed
  EncodingError(String),
  /// Token decoding failed
  DecodingError(String),
  /// Token has expired
  TokenExpired,
  /// Invalid token format
  InvalidToken(String),
  /// JSON serialization/deserialization error
  JsonError(String),
}

impl fmt::Display for DpAuthSessionError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      DpAuthSessionError::EncodingError(msg) => write!(f, "Token encoding error: {msg}"),
      DpAuthSessionError::DecodingError(msg) => write!(f, "Token decoding error: {msg}"),
      DpAuthSessionError::TokenExpired => write!(f, "Token has expired"),
      DpAuthSessionError::InvalidToken(msg) => write!(f, "Invalid token: {msg}"),
      DpAuthSessionError::JsonError(msg) => write!(f, "JSON error: {msg}"),
    }
  }
}

impl std::error::Error for DpAuthSessionError {}
