//! Built-in zero-backtracking regex DFA recognizers for PII, IPs, credentials, and paths.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::OnceLock;

use regex::Regex;

/// Categories of sensitive entities recognized by Loom.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityCategory {
    /// Custom user-defined dictionary term (hostname, codename, personal name).
    CustomDict,
    /// High-entropy API key or bearer token (Anthropic, OpenAI, GitHub, AWS, Slack, GCP).
    ApiKey,
    /// JSON Web Token (`eyJ...`).
    Jwt,
    /// Email address or `user@ipv4` SSH/SCP target.
    Email,
    /// OS user directory path (`C:\Users\<name>`, `/home/<name>`, `/Users/<name>`).
    UserPath,
    /// RFC 4122 128-bit UUID.
    Uuid,
    /// IPv4 address (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, or public routable IPv4).
    Ipv4,
}

impl EntityCategory {
    /// Short canonical code stored in the encrypted SQLite ledger.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CustomDict => "DICT",
            Self::ApiKey => "KEY",
            Self::Jwt => "JWT",
            Self::Email => "MAIL",
            Self::UserPath => "PATH",
            Self::Uuid => "UUID",
            Self::Ipv4 => "IPV4",
        }
    }

    /// Priority rank when two candidate spans overlap (lower number = higher priority).
    pub fn priority(&self) -> u8 {
        match self {
            Self::CustomDict => 1,
            Self::ApiKey => 2,
            Self::Jwt => 3,
            Self::Email => 4,
            Self::UserPath => 5,
            Self::Uuid => 6,
            Self::Ipv4 => 7,
        }
    }
}

pub struct CompiledPatterns {
    pub api_key: Regex,
    pub jwt: Regex,
    pub email: Regex,
    pub user_path: Regex,
    pub uuid: Regex,
    pub ipv4: Regex,
}

pub fn compiled_patterns() -> &'static CompiledPatterns {
    static PATTERNS: OnceLock<CompiledPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| CompiledPatterns {
        api_key: Regex::new(
            r"(?:sk-ant-api03-[A-Za-z0-9_\-]{10,}|sk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{16,}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{12,}|AIza[0-9A-Za-z_\-]{35})",
        )
        .expect("valid api_key regex"),
        jwt: Regex::new(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
        )
        .expect("valid jwt regex"),
        email: Regex::new(
            r"[A-Za-z0-9._%+\-]+@(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,})",
        )
        .expect("valid email regex"),
        user_path: Regex::new(
            r"(?:[A-Za-z]:\\Users\\[A-Za-z0-9._\-]+|/home/[A-Za-z0-9._\-]+|/Users/[A-Za-z0-9._\-]+)",
        )
        .expect("valid user_path regex"),
        uuid: Regex::new(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        )
        .expect("valid uuid regex"),
        ipv4: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("valid ipv4 regex"),
    })
}

/// Returns `true` if `ip` is a sensitive IPv4 address that should be woven, and `false` if it is
/// already a sterile RFC 5737 documentation IP, loopback (`127.x.x.x`), broadcast, or `0.0.0.0`.
pub fn should_scrub_ipv4(ip_str: &str) -> Option<Ipv4Addr> {
    let ip = Ipv4Addr::from_str(ip_str).ok()?;
    let o = ip.octets();

    // Skip loopback (127.0.0.0/8), unspecified (0.0.0.0), broadcast (255.255.255.255), or .0.0 subnet base labels
    if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || (o[2] == 0 && o[3] == 0) {
        return None;
    }
    // Skip RFC 5737 documentation blocks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return None;
    }
    // Skip Loom's own synthetic FPE output block (10.244.0.0/16) so re-weaving is idempotent
    if o[0] == 10 && o[1] == 244 {
        return None;
    }
    Some(ip)
}

/// Returns `true` if `uuid_str` is a real UUID rather than the Nil UUID or RFC 4122 canonical doc example.
pub fn should_scrub_uuid(uuid_str: &str) -> bool {
    let lower = uuid_str.to_ascii_lowercase();
    !(lower == "00000000-0000-0000-0000-000000000000"
        || lower == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
}

/// Returns `true` if `email` is already a sterile RFC 2606 example address (`@example.com`,
/// `@example.org`, `@example.net`, `@users.noreply.github.com`) or RFC 5737 (`@192.0.2.`).
pub fn should_scrub_email(email: &str) -> bool {
    let lower = email.to_ascii_lowercase();
    if lower.ends_with("@users.noreply.github.com")
        || lower.ends_with("@example.com")
        || lower.ends_with("@example.org")
        || lower.ends_with("@example.net")
        || lower.contains("@192.0.2.")
        || lower.contains("@198.51.100.")
        || lower.contains("@203.0.113.")
    {
        return false;
    }
    if lower.starts_with("id_") && lower.contains("@10.244.") {
        return false;
    }
    true
}

/// Returns `true` if `path_match` is a real OS user path rather than an already-woven `user_` path.
pub fn should_scrub_user_path(path_match: &str) -> bool {
    let lower = path_match.to_ascii_lowercase();
    !(lower.ends_with("\\user_sterile")
        || lower.contains("\\user_")
        || lower.contains("/user_")
        || lower.ends_with("\\public")
        || lower.ends_with("\\default"))
}
