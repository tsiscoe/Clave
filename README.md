# Loom (`loom-scrubber`)

[![CI](https://github.com/tsiscoe/Loom/actions/workflows/ci.yml/badge.svg)](https://github.com/tsiscoe/Loom/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust: 2024 Edition](https://img.shields.io/badge/Rust-2024_Edition-orange.svg)](Cargo.toml)
[![Safety: #![forbid(unsafe_code)]](https://img.shields.io/badge/unsafe-forbid-success.svg)](src/lib.rs)

**Loom** is a pure-Rust, bidirectional, format-preserving cryptographic PII, IP, and secret pseudonymizer for LLM prompts, production logs, configuration files, and public git repositories.

---

## Why Loom?

Traditional one-way regex redactors replace sensitive values with `[REDACTED]`. That destroys structural semantics:
- If three distinct cluster nodes (`192.168.1.10`, `192.168.1.20`, `192.168.1.30`) are all replaced with `[REDACTED]`, an LLM or external reviewer can no longer trace which node failed or how packets flowed.
- If an LLM generates a code patch or config fix containing `[REDACTED]`, you have to manually hunt and replace every placeholder.

**Loom** solves both problems using **Format-Preserving Encryption (FPE)** and an **AEAD-Encrypted Bidirectional Ledger (`XChaCha20-Poly1305`)**:
1. **`loom weave` (Pseudonymize):** Deterministically transforms sensitive entities into **syntactically valid RFC 5737 / RFC 2606 equivalents** (`192.168.42.19:8080` -> `10.244.183.91:8080`, `operator@corp.internal` -> `id_7f9a2c1b@example.com`, `C:\Users\alice\app` -> `C:\Users\user_4c8e19a2\app`, `778553cf-3b5e-4eff-9f70-78d7c96964e8` -> `a4190c8e-912b-4d03-8e11-3c9f72a104b6`).
2. **`loom unweave` (Restore):** Uses SIMD `Aho-Corasick` (`LeftmostLongest`) plus stateless 8-round `BLAKE3` Feistel FPE inversion to restore every synthetic token in an LLM's response or patch back to its exact original value in milliseconds.
3. **`loom audit` (CI & Pre-Publish Sterility Gate):** Scans an entire git repository (respecting `.gitignore`) and flags any leaked IPs, emails, API keys, JWTs, user paths, or custom project codenames before you push to a public remote.

---

## Cryptographic & Security Architecture

| Layer | Primitive | Implementation Detail |
| :--- | :--- | :--- |
| **Memory & Type Safety** | `#![forbid(unsafe_code)]` + `ZeroizeOnDrop` | Zero `unsafe` blocks in the entire crate; all key material and decrypted buffers are wiped on drop. |
| **Key Derivation** | `Argon2id` (`m=64 MiB, t=3, p=4`) + `HKDF-SHA256` | Expands three domain-separated 256-bit subkeys (`loom-v1-fpe-key`, `loom-v1-token-mac-key`, `loom-v1-ledger-aead-key`). |
| **Bijective FPE** | 8-Round Balanced Feistel Network (`BLAKE3` PRF) | Stateless $1\text{-to-}1$ mathematical bijection over 16-bit (`192.168.0.0/16` <-> `10.244.0.0/16`), 32-bit, and 128-bit (`UUIDv4`) domains. |
| **Encrypted Token Ledger** | `XChaCha20-Poly1305` (192-bit nonce) + SQLite WAL | Stores variable-length mappings encrypted at rest with contextual AAD (`loom-v1\|id\|category\|field`) and keyed `BLAKE3` blind-index lookup MACs. |
| **Filesystem ACLs** | `icacls /inheritance:r` (Win) / `0700` & `0600` (Unix) | Restricts ledger directory and `.db` file access exclusively to the current OS user. |
| **Terminal Sanitization** | `sanitize_terminal_str` (`CWE-150`) | Strips C0/C1 control characters and ANSI/OSC escape sequences before rendering untrusted logs in `loom tui`. |

---

## Quick Start

### 1. Build & Install from Source

```bash
git clone https://github.com/tsiscoe/Loom.git
cd Loom
cargo install --path .
```

### 2. Pipe Logs or Diffs Through `loom weave` & `loom unweave`

```bash
# Set passphrase in environment or use --keyring to store in OS native credential manager
export LOOM_PASSPHRASE="your-master-passphrase"

# Scrub a sensitive log or git diff before sending to an LLM
git diff | loom weave > sterile.patch

# Restore the LLM's patched output back to your real local IPs, paths, and hostnames
loom unweave -i llm_response.patch -o restored.patch
```

### 3. Register Custom Project Codenames or Hostnames (`loom dict`)

```bash
loom dict add --term "BastionProdNode" --alias "node_alpha_01"
loom dict list
```

### 4. Audit or Sterilize a Repository (`loom audit` / `loom weave --dir`)

```bash
# Scan a repository and fail CI if any PII, internal IP, or key is found
loom audit ./my-repo --fail-on-leak

# Recursively scrub all UTF-8 files in a directory in-place
loom weave --dir ./my-repo
```

### 5. Interactive Ratatui Side-by-Side Diff Viewer (`loom tui`)

```bash
loom tui --file crash.log
```

---

## License

Licensed under the [MIT License](LICENSE).
