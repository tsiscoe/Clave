# Changelog

All notable changes to **Loom** are documented in this file.

## [0.1.0] - 2026-11-12

### Added
- **Cryptographic Core (`src/crypto/`):** `Argon2id` (`m=64 MiB, t=3, p=4`) + `HKDF-SHA256` domain-separated subkey derivation (`fpe_key`, `mac_key`, `aead_key`) + `XChaCha20-Poly1305` AEAD with `ZeroizeOnDrop`.
- **Bijective Format-Preserving Encryption (`src/crypto/fpe.rs`):** 8-round balanced Feistel network keyed with `BLAKE3` PRF for stateless 16-bit (`192.168.0.0/16` <-> `10.244.0.0/16`), 32-bit, 64-bit, and 128-bit (`UUIDv4`) bijections.
- **Blind-Indexed AEAD SQLite Ledger (`src/store/mod.rs`):** Bundled `rusqlite 0.42.0` (`SQLite 3.51.2+`) WAL store with row-contextual AAD binding and owner-only ACL enforcement (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix).
- **Hybrid SIMD Detector (`src/detector/`):** `Aho-Corasick` (`LeftmostLongest`) custom dictionary matcher + zero-backtracking `regex` DFA recognizers across 7 entity classes (`DICT`, `KEY`, `JWT`, `MAIL`, `PATH`, `UUID`, `IPV4`).
- **CLI & Ratatui v0.30+ Diff Viewer (`src/cli.rs`, `src/tui/`):** Added `loom weave`, `loom unweave`, `loom clip`, `loom audit`, `loom dict`, and `loom tui` with `sanitize_terminal_str` ANSI/OSC stripping.
