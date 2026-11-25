//! Encrypted SQLite WAL Token Mapping Ledger (`loom.db`) with owner-only ACL enforcement.
//!
//! Security Invariants:
//! 1. **Zero Plaintext on Disk:** Both the real sensitive token and its synthetic replacement
//!    are stored as `XChaCha20-Poly1305` ciphertexts bound to row-contextual AAD
//!    (`entry_id|category|loom-v1`).
//! 2. **Keyed BLAKE3 Blind Indexing:** Lookups by real value or synthetic token use
//!    `compute_lookup_mac(mac_key, ...)` so an attacker inspecting `loom.db` without the
//!    master key sees only 256-bit random MAC digests and AEAD ciphertexts.
//! 3. **Strict Owner-Only ACLs:** Enforces `icacls /inheritance:r` on Windows and `0700`/`0600`
//!    on Unix upon creation and open.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::{
    MasterSeed, SALT_LEN, SubKeys, aead_decrypt, aead_encrypt, compute_lookup_mac,
    constant_time_eq_32, generate_salt,
};

/// Decrypted bidirectional mapping record held in memory during a session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenMapping {
    pub id: String,
    pub category: String,
    pub real_value: String,
    pub synthetic_value: String,
    pub created_at: String,
}

/// Encrypted SQLite WAL store for bidirectional token mappings and custom user dictionary rules.
pub struct LoomStore {
    conn: Connection,
    db_path: PathBuf,
    subkeys: SubKeys,
}

impl LoomStore {
    /// Open or initialize an encrypted `LoomStore` at `db_path` using the given passphrase.
    pub fn open_with_passphrase(db_path: &Path, passphrase: &[u8], fast_kdf: bool) -> Result<Self> {
        if let Some(parent) = db_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create vault directory {}", parent.display())
            })?;
        }

        let conn = Connection::open(db_path)
            .with_context(|| format!("failed to open SQLite ledger at {}", db_path.display()))?;

        conn.busy_timeout(std::time::Duration::from_millis(5_000))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "secure_delete", "ON")?;

        if !fast_kdf {
            enforce_db_and_sidecar_acls(db_path)?;
        }

        Self::init_schema(&conn)?;

        let (salt, expected_verifier) = match Self::load_vault_meta(&conn)? {
            Some((s, v)) => (s, Some(v)),
            None => (generate_salt(), None),
        };

        let seed = if fast_kdf {
            MasterSeed::derive_fast_for_test(passphrase, &salt)?
        } else {
            MasterSeed::derive_from_passphrase(passphrase, &salt)?
        };

        let verifier = seed.compute_verifier(&salt)?;
        if let Some(expected) = expected_verifier {
            if !constant_time_eq_32(&verifier, &expected) {
                return Err(anyhow!(
                    "Invalid passphrase or key for Loom ledger at {}",
                    db_path.display()
                ));
            }
        } else {
            Self::save_vault_meta(&conn, &salt, &verifier)?;
        }

        let subkeys = seed.derive_subkeys(&salt)?;

        Ok(Self {
            conn,
            db_path: db_path.to_path_buf(),
            subkeys,
        })
    }

    /// Open an in-memory SQLite ledger for high-speed property-based testing (`proptest`).
    pub fn open_in_memory_for_test(passphrase: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory SQLite")?;
        Self::init_schema(&conn)?;
        let salt = [0x5Au8; SALT_LEN];
        let seed = MasterSeed::derive_fast_for_test(passphrase, &salt)?;
        let verifier = seed.compute_verifier(&salt)?;
        Self::save_vault_meta(&conn, &salt, &verifier)?;
        let subkeys = seed.derive_subkeys(&salt)?;
        Ok(Self {
            conn,
            db_path: PathBuf::from(":memory:"),
            subkeys,
        })
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS loom_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                salt BLOB NOT NULL,
                verifier BLOB NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS token_mappings (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                real_mac BLOB NOT NULL UNIQUE,
                synthetic_mac BLOB NOT NULL UNIQUE,
                real_ciphertext BLOB NOT NULL,
                synthetic_ciphertext BLOB NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_token_real_mac ON token_mappings(real_mac);
            CREATE INDEX IF NOT EXISTS idx_token_syn_mac ON token_mappings(synthetic_mac);",
        )
        .context("failed to initialize Loom SQLite schema")?;
        Ok(())
    }

    fn load_vault_meta(conn: &Connection) -> Result<Option<([u8; SALT_LEN], [u8; 32])>> {
        let row: Option<(Vec<u8>, Vec<u8>)> = conn
            .query_row(
                "SELECT salt, verifier FROM loom_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((salt_vec, ver_vec)) = row {
            let salt: [u8; SALT_LEN] = salt_vec
                .try_into()
                .map_err(|_| anyhow!("corrupted salt length in loom_meta"))?;
            let verifier: [u8; 32] = ver_vec
                .try_into()
                .map_err(|_| anyhow!("corrupted verifier length in loom_meta"))?;
            Ok(Some((salt, verifier)))
        } else {
            Ok(None)
        }
    }

    fn save_vault_meta(
        conn: &Connection,
        salt: &[u8; SALT_LEN],
        verifier: &[u8; 32],
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO loom_meta (id, salt, verifier, schema_version) VALUES (1, ?1, ?2, 1)",
            params![salt.as_slice(), verifier.as_slice()],
        )?;
        Ok(())
    }

    /// Return the path to the backing SQLite file.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Return a reference to the active [`SubKeys`].
    pub fn subkeys(&self) -> &SubKeys {
        &self.subkeys
    }

    /// Look up an existing synthetic token for `(category, real_value)` or insert `new_synthetic`
    /// if not yet recorded. Guarantees 1-to-1 idempotence across sessions.
    pub fn get_or_insert_mapping(
        &self,
        category: &str,
        real_value: &str,
        new_synthetic: &str,
    ) -> Result<String> {
        if let Some(existing) = self.lookup_synthetic_by_real(category, real_value)? {
            return Ok(existing);
        }

        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now().to_rfc3339();
        let real_mac = compute_lookup_mac(&self.subkeys.mac_key, category, real_value);
        let syn_mac = compute_lookup_mac(&self.subkeys.mac_key, "SYN", new_synthetic);

        let aad_real = Self::build_aad(&id, category, "real");
        let aad_syn = Self::build_aad(&id, category, "synthetic");

        let real_ct = aead_encrypt(&self.subkeys.aead_key, real_value.as_bytes(), &aad_real)?;
        let syn_ct = aead_encrypt(&self.subkeys.aead_key, new_synthetic.as_bytes(), &aad_syn)?;

        self.conn.execute(
            "INSERT INTO token_mappings (
                id, category, real_mac, synthetic_mac, real_ciphertext, synthetic_ciphertext, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                category,
                real_mac.as_slice(),
                syn_mac.as_slice(),
                real_ct,
                syn_ct,
                created_at
            ],
        )?;

        Ok(new_synthetic.to_string())
    }

    /// Explicitly register or update a custom dictionary term (`real_value` <-> `synthetic_alias`).
    pub fn upsert_custom_term(&self, real_value: &str, synthetic_alias: &str) -> Result<String> {
        let category = "DICT";
        let real_mac = compute_lookup_mac(&self.subkeys.mac_key, category, real_value);
        self.conn.execute(
            "DELETE FROM token_mappings WHERE real_mac = ?1",
            params![real_mac.as_slice()],
        )?;
        self.get_or_insert_mapping(category, real_value, synthetic_alias)
    }

    /// Look up the synthetic token for a given `(category, real_value)`.
    pub fn lookup_synthetic_by_real(
        &self,
        category: &str,
        real_value: &str,
    ) -> Result<Option<String>> {
        let real_mac = compute_lookup_mac(&self.subkeys.mac_key, category, real_value);
        let row: Option<(String, String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT id, category, synthetic_ciphertext FROM token_mappings WHERE real_mac = ?1",
                params![real_mac.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        if let Some((id, cat, syn_ct)) = row {
            let aad_syn = Self::build_aad(&id, &cat, "synthetic");
            let dec = aead_decrypt(&self.subkeys.aead_key, &syn_ct, &aad_syn)?;
            return Ok(Some(dec.into_utf8_string()?));
        }

        // [SEC-02]: For custom `DICT` rules, support case-insensitive lookup so `"alpha_host"`,
        // `"Alpha_Host"`, and `"ALPHA_HOST"` all resolve to the registered `[DICT]` alias!
        if category == "DICT" {
            for m in self.list_all_mappings()? {
                if m.category == "DICT" && m.real_value.eq_ignore_ascii_case(real_value) {
                    return Ok(Some(m.synthetic_value));
                }
            }
        }

        Ok(None)
    }

    /// Look up the original real value for a given `synthetic_value`.
    pub fn lookup_real_by_synthetic(&self, synthetic_value: &str) -> Result<Option<String>> {
        let syn_mac = compute_lookup_mac(&self.subkeys.mac_key, "SYN", synthetic_value);
        let row: Option<(String, String, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT id, category, real_ciphertext FROM token_mappings WHERE synthetic_mac = ?1",
                params![syn_mac.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        if let Some((id, cat, real_ct)) = row {
            let aad_real = Self::build_aad(&id, &cat, "real");
            let dec = aead_decrypt(&self.subkeys.aead_key, &real_ct, &aad_real)?;
            Ok(Some(dec.into_utf8_string()?))
        } else {
            Ok(None)
        }
    }

    /// Load and decrypt all stored [`TokenMapping`] entries (used by `unweave` Aho-Corasick
    /// automaton, `dict list`, and `loom tui`).
    pub fn list_all_mappings(&self) -> Result<Vec<TokenMapping>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, category, real_ciphertext, synthetic_ciphertext, created_at
             FROM token_mappings ORDER BY created_at ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();

        while let Some(r) = rows.next()? {
            let id: String = r.get(0)?;
            let category: String = r.get(1)?;
            let real_ct: Vec<u8> = r.get(2)?;
            let syn_ct: Vec<u8> = r.get(3)?;
            let created_at: String = r.get(4)?;

            let aad_real = Self::build_aad(&id, &category, "real");
            let aad_syn = Self::build_aad(&id, &category, "synthetic");

            let real_value =
                aead_decrypt(&self.subkeys.aead_key, &real_ct, &aad_real)?.into_utf8_string()?;
            let synthetic_value =
                aead_decrypt(&self.subkeys.aead_key, &syn_ct, &aad_syn)?.into_utf8_string()?;

            out.push(TokenMapping {
                id,
                category,
                real_value,
                synthetic_value,
                created_at,
            });
        }
        Ok(out)
    }

    fn build_aad(id: &str, category: &str, field: &str) -> Vec<u8> {
        format!("loom-v1|{id}|{category}|{field}").into_bytes()
    }
}

/// Resolve the default Loom SQLite ledger path (`%APPDATA%\loom\loom.db` or `~/.config/loom/loom.db`).
pub fn default_ledger_path() -> PathBuf {
    if let Ok(override_path) = std::env::var("CLAVE_DB_PATH") {
        return PathBuf::from(override_path);
    }
    let base = dirs::data_local_dir()
        .or_else(dirs::config_dir)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("loom").join("loom.db")
}

/// Enforce strict owner-only ACLs on the SQLite database file and any existing `-wal`/`-shm`
/// sidecar files without mutating parent directory inheritance (`CLAVE-HORDE-02`).
pub fn enforce_db_and_sidecar_acls(db_path: &Path) -> Result<()> {
    enforce_owner_only_acl(db_path, false)?;
    for suffix in ["-wal", "-shm"] {
        let mut os = db_path.as_os_str().to_os_string();
        os.push(suffix);
        let sidecar = PathBuf::from(os);
        if sidecar.exists() {
            enforce_owner_only_acl(&sidecar, false)?;
        }
    }
    Ok(())
}

/// Enforce fail-closed owner-only filesystem ACLs (`icacls /inheritance:r` on Windows, `0700`/`0600` on Unix).
pub fn enforce_owner_only_acl(path: &Path, is_dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if is_dir { 0o700 } else { 0o600 };
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("failed to set Unix mode {:o} on {}", mode, path.display()))?;
        let applied = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if applied != mode {
            return Err(anyhow!(
                "effective Unix mode {:o} != {:o} on {}",
                applied,
                mode,
                path.display()
            ));
        }
    }

    #[cfg(windows)]
    {
        let principal = resolve_windows_owner_principal()?;
        let grant_spec = if is_dir {
            format!("{principal}:(OI)(CI)F")
        } else {
            format!("{principal}:F")
        };
        let output = std::process::Command::new("icacls")
            .arg(path)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg(&grant_spec)
            .output()
            .with_context(|| format!("failed to execute icacls on {}", path.display()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "icacls failed on {} ({}): {} {}",
                path.display(),
                output.status,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn resolve_windows_owner_principal() -> Result<String> {
    if let Ok(out) = std::process::Command::new("whoami").output()
        && out.status.success()
    {
        let who = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !who.is_empty() {
            return Ok(who);
        }
    }
    if let Ok(username) = std::env::var("USERNAME") {
        let trimmed = username.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(anyhow!(
        "unable to resolve Windows owner principal via whoami or USERNAME"
    ))
}
