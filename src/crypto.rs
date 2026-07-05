use argon2::{
    password_hash::rand_core::RngCore,
    Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Generates a secure random 16-byte salt for Argon2id.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit key from the master password and a salt using Argon2id.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let mut derived_key = [0u8; KEY_LEN];
    let params = Params::new(65536, 3, 4, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );
    
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| e.to_string())?;

    Ok(Zeroizing::new(derived_key))
}

/// Derives a 256-bit key using the legacy weak Argon2id parameters (for migration).
pub fn derive_key_legacy(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, String> {
    let mut derived_key = [0u8; KEY_LEN];
    let params = Params::new(15360, 2, 1, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );
    
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut derived_key)
        .map_err(|e| e.to_string())?;

    Ok(Zeroizing::new(derived_key))
}

/// Encrypts plaintext using XChaCha20-Poly1305 with the derived key.
/// Returns `nonce (24 bytes) + ciphertext`.
pub fn encrypt(plaintext: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = OsRng;
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;

    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts a combined payload containing `nonce (24 bytes) + ciphertext`.
pub fn decrypt(encrypted_data: &[u8], key: &[u8; KEY_LEN]) -> Result<Zeroizing<Vec<u8>>, String> {
    if encrypted_data.len() < NONCE_LEN {
        return Err("Encrypted data is too short".to_string());
    }

    let (nonce_bytes, ciphertext) = encrypted_data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);

    let decrypted = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| e.to_string())?;

    Ok(Zeroizing::new(decrypted))
}
