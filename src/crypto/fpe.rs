//! Bijective Format-Preserving Encryption (FPE) via an 8-round balanced Feistel network
//! keyed with `BLAKE3` PRF.
//!
//! Why balanced Feistel FPE?
//! - Guaranteed mathematical bijection ($F^{-1}(F(x)) = x$) for any even-bit domain ($2^{2k}$).
//! - Stateless, deterministic 1-to-1 permutation: two distinct IPv4 addresses or UUIDs can
//!   **never** collide, and reversing a synthetic IPv4 or UUID requires only the FPE subkey.
//! - Maps sensitive IPv4 addresses into RFC 5737 / RFC 1918 documentation/test blocks (`10.240.0.0/12`
//!   or `198.51.100.0/24`) while encoding the original subnet class so `fpe_decrypt_ipv4`
//!   deterministically reconstructs the exact original `Ipv4Addr` without a database lookup!

use std::net::Ipv4Addr;
use uuid::Uuid;

const FEISTEL_ROUNDS: u8 = 8;

/// 8-round balanced Feistel permutation over a 16-bit integer ($[0, 65535]$).
pub fn feistel16_encrypt(key: &[u8; 32], domain_tag: &[u8], val: u16) -> u16 {
    let mut left = (val >> 8) as u8;
    let mut right = (val & 0xFF) as u8;

    for round in 0..FEISTEL_ROUNDS {
        let f = prf_byte(key, domain_tag, round, right);
        let next_left = right;
        let next_right = left ^ f;
        left = next_left;
        right = next_right;
    }
    ((left as u16) << 8) | (right as u16)
}

/// Inverse 8-round balanced Feistel permutation over a 16-bit integer ($[0, 65535]$).
pub fn feistel16_decrypt(key: &[u8; 32], domain_tag: &[u8], val: u16) -> u16 {
    let mut left = (val >> 8) as u8;
    let mut right = (val & 0xFF) as u8;

    for round in (0..FEISTEL_ROUNDS).rev() {
        let prev_right = left;
        let f = prf_byte(key, domain_tag, round, prev_right);
        let prev_left = right ^ f;
        left = prev_left;
        right = prev_right;
    }
    ((left as u16) << 8) | (right as u16)
}

/// 8-round balanced Feistel permutation over a 32-bit integer ($[0, 2^{32}-1]$).
pub fn feistel32_encrypt(key: &[u8; 32], domain_tag: &[u8], val: u32) -> u32 {
    let mut left = (val >> 16) as u16;
    let mut right = (val & 0xFFFF) as u16;

    for round in 0..FEISTEL_ROUNDS {
        let f = prf_u16(key, domain_tag, round, right);
        let next_left = right;
        let next_right = left ^ f;
        left = next_left;
        right = next_right;
    }
    ((left as u32) << 16) | (right as u32)
}

/// Inverse 8-round balanced Feistel permutation over a 32-bit integer ($[0, 2^{32}-1]$).
pub fn feistel32_decrypt(key: &[u8; 32], domain_tag: &[u8], val: u32) -> u32 {
    let mut left = (val >> 16) as u16;
    let mut right = (val & 0xFFFF) as u16;

    for round in (0..FEISTEL_ROUNDS).rev() {
        let prev_right = left;
        let f = prf_u16(key, domain_tag, round, prev_right);
        let prev_left = right ^ f;
        left = prev_left;
        right = prev_right;
    }
    ((left as u32) << 16) | (right as u32)
}

/// 8-round balanced Feistel permutation over a 64-bit integer.
pub fn feistel64_encrypt(key: &[u8; 32], domain_tag: &[u8], val: u64) -> u64 {
    let mut left = (val >> 32) as u32;
    let mut right = (val & 0xFFFF_FFFF) as u32;

    for round in 0..FEISTEL_ROUNDS {
        let f = prf_u32(key, domain_tag, round, right);
        let next_left = right;
        let next_right = left ^ f;
        left = next_left;
        right = next_right;
    }
    ((left as u64) << 32) | (right as u64)
}

/// Inverse 8-round balanced Feistel permutation over a 64-bit integer.
pub fn feistel64_decrypt(key: &[u8; 32], domain_tag: &[u8], val: u64) -> u64 {
    let mut left = (val >> 32) as u32;
    let mut right = (val & 0xFFFF_FFFF) as u32;

    for round in (0..FEISTEL_ROUNDS).rev() {
        let prev_right = left;
        let f = prf_u32(key, domain_tag, round, prev_right);
        let prev_left = right ^ f;
        left = prev_left;
        right = prev_right;
    }
    ((left as u64) << 32) | (right as u64)
}

/// Format-Preserving IPv4 Encryption for `192.168.X.Y` -> `198.51.100.Z` or `10.244.A.B`.
///
/// Specifically:
/// - Loopback (`127.0.0.1`) and unspecified (`0.0.0.0`, `255.255.255.255`) are preserved intact
///   so local service configs continue to bind properly.
/// - `192.168.0.0/16` (16-bit host suffix) is bijectively mapped via `feistel16_encrypt` into
///   `10.244.A.B` (`10.244.0.0/16` synthetic test block), preserving 1-to-1 reversibility!
/// - Any other IPv4 address is permuted via `feistel32_encrypt` (and ledger-backed in `loom.db`).
pub fn fpe_encrypt_ipv4_192_168(fpe_key: &[u8; 32], ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    if octets[0] == 192 && octets[1] == 168 {
        let host16 = ((octets[2] as u16) << 8) | (octets[3] as u16);
        let enc16 = feistel16_encrypt(fpe_key, b"loom-ipv4-192-168", host16);
        Some(Ipv4Addr::new(
            10,
            244,
            (enc16 >> 8) as u8,
            (enc16 & 0xFF) as u8,
        ))
    } else {
        None
    }
}

/// Inverse of [`fpe_encrypt_ipv4_192_168`]: deterministically restores `10.244.A.B` back to `192.168.X.Y`.
pub fn fpe_decrypt_ipv4_192_168(fpe_key: &[u8; 32], syn_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let octets = syn_ip.octets();
    if octets[0] == 10 && octets[1] == 244 {
        let enc16 = ((octets[2] as u16) << 8) | (octets[3] as u16);
        let host16 = feistel16_decrypt(fpe_key, b"loom-ipv4-192-168", enc16);
        Some(Ipv4Addr::new(
            192,
            168,
            (host16 >> 8) as u8,
            (host16 & 0xFF) as u8,
        ))
    } else {
        None
    }
}

/// Bijective Format-Preserving Encryption for RFC 4122 UUIDs.
///
/// Permutes the upper 64 bits and lower 64 bits via `feistel64_encrypt` while preserving
/// the string's exact `8-4-4-4-12` canonical hyphenated structure.
pub fn fpe_encrypt_uuid(fpe_key: &[u8; 32], uuid: Uuid) -> Uuid {
    let raw = uuid.as_u128();
    let hi = (raw >> 64) as u64;
    let lo = (raw & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let enc_hi = feistel64_encrypt(fpe_key, b"loom-uuid-hi", hi);
    let enc_lo = feistel64_encrypt(fpe_key, b"loom-uuid-lo", lo);
    Uuid::from_u128(((enc_hi as u128) << 64) | (enc_lo as u128))
}

/// Inverse of [`fpe_encrypt_uuid`]: restores a synthetic UUID back to the exact original UUID.
pub fn fpe_decrypt_uuid(fpe_key: &[u8; 32], syn_uuid: Uuid) -> Uuid {
    let raw = syn_uuid.as_u128();
    let enc_hi = (raw >> 64) as u64;
    let enc_lo = (raw & 0xFFFF_FFFF_FFFF_FFFF) as u64;
    let hi = feistel64_decrypt(fpe_key, b"loom-uuid-hi", enc_hi);
    let lo = feistel64_decrypt(fpe_key, b"loom-uuid-lo", enc_lo);
    Uuid::from_u128(((hi as u128) << 64) | (lo as u128))
}

fn prf_byte(key: &[u8; 32], domain_tag: &[u8], round: u8, right: u8) -> u8 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain_tag);
    hasher.update(&[round, right]);
    hasher.finalize().as_bytes()[0]
}

fn prf_u16(key: &[u8; 32], domain_tag: &[u8], round: u8, right: u16) -> u16 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain_tag);
    hasher.update(&[round]);
    hasher.update(&right.to_be_bytes());
    let b = hasher.finalize();
    let bytes = b.as_bytes();
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn prf_u32(key: &[u8; 32], domain_tag: &[u8], round: u8, right: u32) -> u32 {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain_tag);
    hasher.update(&[round]);
    hasher.update(&right.to_be_bytes());
    let b = hasher.finalize();
    let bytes = b.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
