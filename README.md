# DP Auth Session Service

A standalone Rust crate for secure session token management using AES-256-GCM encryption.

## Features

- **Secure Token Encoding/Decoding**: Uses AES-256-GCM encryption with random nonces
- **Session Payload Management**: Handles user ID and timestamp information
- **Expiration Validation**: Automatically validates token expiration
- **Comprehensive Error Handling**: Detailed error types for different failure scenarios
- **Zero External Dependencies**: No database or user management dependencies

## Usage

Add this to your `Cargo.toml`:

<!-- x-release-please-start-version -->
```toml
[dependencies]
dp-auth-session-service = { git = "https://github.com/dimensionalpocket/auth-session-service", tag = "0.1.0" }
```
<!-- x-release-please-end -->

### Basic Example

```rust
use dp_auth_session_service::{DpAuthSessionService, DpAuthSessionPayload, DpAuthSessionError};

fn main() -> Result<(), DpAuthSessionError> {
    // Use a proper 32-byte secret key in production
    let secret = &[0u8; 32];
    
    // Create a session payload for user ID 123
    let payload = DpAuthSessionService::create_payload(123);
    println!("Created session for user: {}", payload.sub);
    
    // Encode the payload into a secure token
    let token = DpAuthSessionService::encode_token(&payload, secret)?;
    println!("Generated token: {}", token);
    
    // Decode the token back to payload
    let decoded_payload = DpAuthSessionService::decode_token(&token, secret)?;
    println!("Decoded user ID: {}", decoded_payload.sub);
    
    assert_eq!(payload.sub, decoded_payload.sub);
    Ok(())
}
```

### Error Handling

```rust
use dp_auth_session_service::{DpAuthSessionService, DpAuthSessionError};

let secret = &[0u8; 32];
let invalid_token = "invalid-token";

match DpAuthSessionService::decode_token(invalid_token, secret) {
    Ok(payload) => println!("Valid token for user: {}", payload.sub),
    Err(DpAuthSessionError::TokenExpired) => println!("Token has expired"),
    Err(DpAuthSessionError::InvalidToken(msg)) => println!("Invalid token: {}", msg),
    Err(DpAuthSessionError::DecodingError(msg)) => println!("Decoding failed: {}", msg),
    Err(e) => println!("Other error: {}", e),
}
```

## API Reference

### `DpAuthSessionService`

The main service struct providing static methods for token operations.

#### Methods

- `create_payload(user_id: i64) -> DpAuthSessionPayload`
  - Creates a new session payload with current timestamp and 3-day expiration
  
- `encode_token(payload: &DpAuthSessionPayload, secret: &[u8]) -> Result<String, DpAuthSessionError>`
  - Encrypts a session payload into a base64-encoded token
  - Requires a 32-byte secret key for AES-256-GCM encryption
  
- `decode_token(token: &str, secret: &[u8]) -> Result<DpAuthSessionPayload, DpAuthSessionError>`
  - Decrypts and validates a token, returning the session payload
  - Automatically checks for token expiration

### `DpAuthSessionPayload`

Session information structure.

#### Fields

- `sub: i64` - Subject (user ID)
- `iat: i64` - Issued at timestamp (seconds since Unix epoch)
- `exp: i64` - Expiration timestamp (seconds since Unix epoch)

### `DpAuthSessionError`

Error types for session operations.

#### Variants

- `EncodingError(String)` - Token encoding failed
- `DecodingError(String)` - Token decoding failed  
- `TokenExpired` - Token has expired
- `InvalidToken(String)` - Invalid token format
- `JsonError(String)` - JSON serialization/deserialization error

## Security Considerations

- **Secret Key**: Use a cryptographically secure 32-byte secret key
- **Key Rotation**: Consider implementing key rotation for long-running applications
- **Token Storage**: Store tokens securely (HTTPS only cookies, secure headers)
- **Expiration**: Default 3-day expiration can be customized by creating payloads manually

## Testing

Run the test suite:

```bash
cargo test
```

The crate includes comprehensive unit and integration tests covering:
- Token encoding/decoding roundtrips
- Expiration validation
- Error conditions
- Edge cases (large user IDs, invalid tokens, etc.)

## License

MIT License - see [LICENSE](./LICENSE) file for details.
