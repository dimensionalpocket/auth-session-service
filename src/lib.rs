//! # DP Auth Session Service
//!
//! A standalone authentication session service providing secure token encoding and decoding
//! functionality using AES-256-GCM encryption.
//!
//! ## Features
//!
//! - Secure token encoding/decoding with AES-256-GCM encryption
//! - Session payload management with expiration handling
//! - Comprehensive error handling
//! - No external dependencies on databases or user management
//!
//! ## Usage
//!
//! ```rust
//! use dp_auth_session_service::{DpAuthSessionService, DpAuthSessionPayload};
//!
//! // Create a session payload
//! let payload = DpAuthSessionService::create_payload(123);
//!
//! // Encode to token
//! let secret = &[0u8; 32]; // Use a proper 32-byte secret in production
//! let token = DpAuthSessionService::encode_token(&payload, secret)?;
//!
//! // Decode token back to payload
//! let decoded = DpAuthSessionService::decode_token(&token, secret)?;
//! assert_eq!(payload.sub, decoded.sub);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod error;
pub mod payload;
pub mod service;

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use error::DpAuthSessionError;
pub use payload::DpAuthSessionPayload;
pub use service::DpAuthSessionService;
