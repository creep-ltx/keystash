use argon2::{
    password_hash::rand_core::RngCore,
    Argon2, Params, Version,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

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

/// Derives a second, independent key for SQLCipher's whole-database page encryption
/// from the same Argon2id master key via HKDF-SHA256. This is deliberately a one-way
/// derivation (HKDF cannot be inverted): a compromise of the SQLCipher layer alone
/// (e.g. a bug in the page cipher, or the raw key being recovered from that layer)
/// exposes this key but not the master key, so it cannot be used to decrypt the
/// `encrypted_password` / `encrypted_notes` fields, which are encrypted directly with
/// the master key. Leaking the master key trivially lets you recompute this key too,
/// but at that point the field-level ciphertexts are already exposed, so there is no
/// loss of security from that direction.
pub fn derive_sqlcipher_key(master_key: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"keystash-sqlcipher-page-key-v1", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Zeroizing::new(okm)
}

/// Derives a third, independent key for the local HIBP breach-count cache from
/// the same Argon2id master key via HKDF-SHA256, mirroring `derive_sqlcipher_key`.
/// Keying the cache this way (see `hibp_cache_fingerprint`) means an attacker who
/// only compromises the SQLCipher layer -- exactly the threat model the README's
/// defense-in-depth claim is about -- cannot use the cache's lookup keys to test
/// candidate passwords offline, unlike a raw, unsalted SHA-256 of each password.
fn derive_hibp_cache_key(master_key: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(b"keystash-hibp-cache-key-v1", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Zeroizing::new(okm)
}

/// Computes the lookup key used for the local HIBP cache: HMAC-SHA256 of the
/// password, keyed on `derive_hibp_cache_key(master_key)`. Because the key is
/// derived from the master key, rotating the master password (a fresh salt,
/// hence a fresh master key) naturally and silently invalidates every entry
/// in the cache -- callers should not try to carry old entries over.
pub fn hibp_cache_fingerprint(password: &[u8], master_key: &[u8; KEY_LEN]) -> String {
    let cache_key = derive_hibp_cache_key(master_key);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&*cache_key).expect("HMAC-SHA256 accepts any key length");
    mac.update(password);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Formats a raw key as the hex literal SQLCipher's `PRAGMA key = "x'...'"` expects.
pub fn pragma_key_hex(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut hex = String::with_capacity(KEY_LEN * 2);
    for b in key.iter() {
        hex.push_str(&format!("{:02x}", b));
    }
    Zeroizing::new(hex)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hibp_fingerprint_is_not_raw_sha256() {
        let master_key = [0x42u8; KEY_LEN];
        let password = b"hunter2";

        let fingerprint = hibp_cache_fingerprint(password, &master_key);

        // A raw SHA-256 of the password would be reproducible by anyone who
        // only has the SQLCipher layer (i.e. without the master key) -- the
        // entire point of HMAC-keying it. Confirm the two diverge.
        use sha2::Digest;
        let raw_sha256_hex: String = Sha256::digest(password)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        assert_ne!(fingerprint, raw_sha256_hex);
    }

    #[test]
    fn hibp_fingerprint_is_deterministic_and_key_dependent() {
        let key_a = [0x11u8; KEY_LEN];
        let key_b = [0x22u8; KEY_LEN];
        let password = b"correct horse battery staple";

        // Same master key + password -> same fingerprint every time (needed
        // for cache lookups to hit at all).
        assert_eq!(
            hibp_cache_fingerprint(password, &key_a),
            hibp_cache_fingerprint(password, &key_a)
        );

        // Different master key (i.e. after a rotation) -> different
        // fingerprint, which is what makes the old cache entries unmatchable.
        assert_ne!(
            hibp_cache_fingerprint(password, &key_a),
            hibp_cache_fingerprint(password, &key_b)
        );
    }
}
