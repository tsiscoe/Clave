//! Cryptographic key hierarchy, BLAKE3 keyed PRF, and XChaCha20-Poly1305 AEAD envelope.
//!
//! Key Derivation Hierarchy:
//! ```text
//! Master Passphrase / Keyring Seed + 128-bit Vault Salt
//!         │
//!         ▼  Argon2id (m = 65536 KiB, t = 3, p = 4)
//! [32-Byte Master Seed] (ZeroizeOnDrop)
//!         │
//!         ├──► HKDF-SHA256("loom-v1-fpe-key")        ──► 256-bit Bijective Feistel FPE Key
//!         ├──► HKDF-SHA256("loom-v1-token-mac-key")  ──► 256-bit BLAKE3 Deterministic Token Key
//!         └──► HKDF-SHA256("loom-v1-ledger-aead-key")──► 256-bit XChaCha20-Poly1305 Vault Key
//! ```

pub mod fpe;

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Argon2id memory cost: 64 MiB (65,536 KiB).
pub const ARGON2_M_COST: u32 = 65_536;
/// Argon2id time cost: 3 iterations.
pub const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism: 4 lanes.
pub const ARGON2_P_COST: u32 = 4;
/// XChaCha20-Poly1305 extended nonce size (24 bytes / 192 bits).
pub const XNONCE_LEN: usize = 24;
/// Salt size (16 bytes / 128 bits).
pub const SALT_LEN: usize = 16;

const HKDF_INFO_FPE: &[u8] = b"loom-v1-fpe-key";
const HKDF_INFO_MAC: &[u8] = b"loom-v1-token-mac-key";
const HKDF_INFO_AEAD: &[u8] = b"loom-v1-ledger-aead-key";
const HKDF_INFO_VERIFY: &[u8] = b"loom-v1-key-verifier";

/// 32-byte root cryptographic seed that deterministically zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterSeed([u8; 32]);

/// Domain-separated 256-bit subkeys derived from [`MasterSeed`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SubKeys {
    /// Key for bijective Feistel Format-Preserving Encryption (IPv4, UUIDv4).
    pub fpe_key: [u8; 32],
    /// Key for BLAKE3 deterministic synthetic token generation.
    pub mac_key: [u8; 32],
    /// Key for XChaCha20-Poly1305 encryption of the reversible token ledger.
    pub aead_key: [u8; 32],
}

impl MasterSeed {
    /// Construct a `MasterSeed` directly from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random 32-byte `MasterSeed` from the OS CSPRNG.
    pub fn generate_random() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Return a reference to the underlying 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a 32-byte `MasterSeed` from a user passphrase and 16-byte salt via Argon2id.
    pub fn derive_from_passphrase(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|e| anyhow!("invalid Argon2id parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Fast deterministic derivation for unit/property tests (reduced Argon2id cost).
    pub fn derive_fast_for_test(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let params = Params::new(1024, 1, 1, Some(32))
            .map_err(|e| anyhow!("invalid Argon2id test parameters: {e}"))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase, salt, &mut out)
            .map_err(|e| anyhow!("Argon2id test derivation failed: {e}"))?;
        Ok(Self(out))
    }

    /// Expand the root `MasterSeed` into three domain-separated 256-bit subkeys via HKDF-SHA256.
    pub fn derive_subkeys(&self, salt: &[u8; SALT_LEN]) -> Result<SubKeys> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut fpe_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        let mut aead_key = [0u8; 32];

        hk.expand(HKDF_INFO_FPE, &mut fpe_key)
            .map_err(|_| anyhow!("HKDF expansion failed for fpe_key"))?;
        hk.expand(HKDF_INFO_MAC, &mut mac_key)
            .map_err(|_| anyhow!("HKDF expansion failed for mac_key"))?;
        hk.expand(HKDF_INFO_AEAD, &mut aead_key)
            .map_err(|_| anyhow!("HKDF expansion failed for aead_key"))?;

        Ok(SubKeys {
            fpe_key,
            mac_key,
            aead_key,
        })
    }

    /// Compute a 32-byte key verification tag to detect wrong passphrases on vault open.
    pub fn compute_verifier(&self, salt: &[u8; SALT_LEN]) -> Result<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut verifier = [0u8; 32];
        hk.expand(HKDF_INFO_VERIFY, &mut verifier)
            .map_err(|_| anyhow!("HKDF expansion failed for verifier"))?;
        Ok(verifier)
    }
}

/// Generate a fresh 128-bit cryptographic salt from the OS CSPRNG.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Compute a keyed BLAKE3 hex tag (truncated to `hex_chars` characters) for deterministic synthetic tokens.
pub fn deterministic_token_hex(
    mac_key: &[u8; 32],
    domain: &str,
    plaintext: &str,
    hex_chars: usize,
) -> String {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(domain.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(plaintext.as_bytes());
    let hash = hasher.finalize();
    let full_hex = hash.to_hex();
    let len = hex_chars.clamp(4, 64);
    full_hex[..len].to_string()
}

/// Compute a full 32-byte keyed BLAKE3 lookup digest so the SQLite ledger can index
/// tokens without storing any plaintext or reversible hash on disk.
pub fn compute_lookup_mac(mac_key: &[u8; 32], category: &str, value: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(b"loom-v1-lookup:");
    hasher.update(category.as_bytes());
    hasher.update(&[0x1f]);
    hasher.update(value.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Encrypt a UTF-8 string using XChaCha20-Poly1305 with a 192-bit random nonce and contextual AAD.
/// Returns `nonce (24 bytes) || ciphertext || poly1305_tag (16 bytes)`.
pub fn aead_encrypt(key_bytes: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let mut nonce_bytes = [0u8; XNONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("XChaCha20-Poly1305 encryption failed"))?;

    let mut out = Vec::with_capacity(XNONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a `nonce || ciphertext || tag` blob using XChaCha20-Poly1305 and verify contextual AAD.
pub fn aead_decrypt(key_bytes: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<ZeroizeBuffer> {
    if blob.len() < XNONCE_LEN + 16 {
        return Err(anyhow!(
            "ciphertext blob too short ({} bytes, minimum {})",
            blob.len(),
            XNONCE_LEN + 16
        ));
    }
    let (nonce_bytes, ciphertext) = blob.split_at(XNONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key_bytes));
    let nonce = XNonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            anyhow!("XChaCha20-Poly1305 authentication failed (wrong key or tampered AAD)")
        })?;

    Ok(ZeroizeBuffer(plaintext))
}

/// Zeroizing byte vector wrapper for decrypted secrets.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ZeroizeBuffer(pub Vec<u8>);

impl ZeroizeBuffer {
    /// Convert decrypted bytes into a UTF-8 `String`.
    pub fn into_utf8_string(self) -> Result<String> {
        String::from_utf8(self.0.clone()).context("decrypted payload is not valid UTF-8")
    }
}
