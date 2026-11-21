//! Bidirectional `weave` (pseudonymize) and `unweave` (restore) stream processing engine.

pub mod repo;

use std::net::Ipv4Addr;
use std::str::FromStr;

use aho_corasick::{AhoCorasickBuilder, MatchKind};
use anyhow::Result;
use uuid::Uuid;

use crate::crypto::{
    deterministic_token_hex,
    fpe::{
        feistel16_encrypt, fpe_decrypt_ipv4_192_168, fpe_encrypt_ipv4_192_168, fpe_encrypt_uuid,
    },
};
use crate::detector::{
    DetectedSpan, LoomDetector,
    patterns::{EntityCategory, compiled_patterns},
};
use crate::store::LoomStore;

/// Statistics and span telemetry returned by a `weave` operation.
#[derive(Debug, Clone)]
pub struct WeaveOutcome {
    pub woven_text: String,
    pub replacements_count: usize,
    pub spans: Vec<DetectedSpan>,
}

/// Statistics returned by an `unweave` restoration operation.
#[derive(Debug, Clone)]
pub struct UnweaveOutcome {
    pub restored_text: String,
    pub restored_count: usize,
}

/// Primary Loom engine binding the encrypted SQLite ledger (`LoomStore`) and SIMD detector.
pub struct LoomEngine<'a> {
    store: &'a LoomStore,
}

impl<'a> LoomEngine<'a> {
    /// Create a new `LoomEngine` backed by `store`.
    pub fn new(store: &'a LoomStore) -> Self {
        Self { store }
    }

    /// Build a [`LoomDetector`] populated with all custom `DICT` terms stored in `self.store`.
    pub fn build_detector(&self) -> Result<LoomDetector> {
        let all = self.store.list_all_mappings()?;
        let custom_terms: Vec<String> = all
            .into_iter()
            .filter(|m| m.category == "DICT")
            .map(|m| m.real_value)
            .collect();
        Ok(LoomDetector::new(custom_terms))
    }

    /// Weave (pseudonymize) an input UTF-8 string, recording every bidirectional mapping in
    /// the encrypted SQLite WAL ledger (`loom.db`) and returning [`WeaveOutcome`].
    pub fn weave_text(&self, input: &str) -> Result<WeaveOutcome> {
        let detector = self.build_detector()?;
        let spans = detector.detect_spans(input);
        if spans.is_empty() {
            return Ok(WeaveOutcome {
                woven_text: input.to_string(),
                replacements_count: 0,
                spans,
            });
        }

        let mut out = String::with_capacity(input.len() + 64);
        let mut cursor = 0usize;

        for span in &spans {
            if span.start > cursor {
                out.push_str(&input[cursor..span.start]);
            }
            let synthetic = self.synthesize_and_record(span.category, &span.matched_text)?;
            out.push_str(&synthetic);
            cursor = span.end;
        }

        if cursor < input.len() {
            out.push_str(&input[cursor..]);
        }

        Ok(WeaveOutcome {
            woven_text: out,
            replacements_count: spans.len(),
            spans,
        })
    }

    /// Unweave (restore) a previously woven UTF-8 string back to its exact original identifiers.
    ///
    /// Uses a two-stage restoration pipeline:
    /// 1. **SIMD `Aho-Corasick` (`LeftmostLongest`)** over all synthetic tokens stored in `loom.db`.
    /// 2. **Stateless Feistel FPE Inversion** for any `10.244.A.B` IPv4 address that was woven on
    ///    another machine sharing the same passphrase/key without a synced `loom.db` file!
    pub fn unweave_text(&self, woven: &str) -> Result<UnweaveOutcome> {
        let mappings = self.store.list_all_mappings()?;
        let mut restored_count = 0usize;

        // Stage 1: Aho-Corasick over ledger mappings (sorted longest synthetic token first)
        let mut pairs: Vec<(String, String)> = mappings
            .into_iter()
            .map(|m| (m.synthetic_value, m.real_value))
            .collect();
        pairs.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        pairs.dedup_by(|a, b| a.0 == b.0);

        let stage1 = if pairs.is_empty() {
            woven.to_string()
        } else {
            let patterns: Vec<&str> = pairs.iter().map(|(s, _)| s.as_str()).collect();
            let ac = AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .build(&patterns)?;

            let mut buf = String::with_capacity(woven.len());
            let mut cursor = 0usize;
            for m in ac.find_iter(woven) {
                if m.start() > cursor {
                    buf.push_str(&woven[cursor..m.start()]);
                }
                buf.push_str(&pairs[m.pattern().as_usize()].1);
                restored_count += 1;
                cursor = m.end();
            }
            if cursor < woven.len() {
                buf.push_str(&woven[cursor..]);
            }
            buf
        };

        // Stage 2: Stateless Feistel FPE inversion for any remaining `10.244.A.B` IPv4 tokens
        let ipv4_re = &compiled_patterns().ipv4;
        let fpe_key = &self.store.subkeys().fpe_key;
        let mut final_buf = String::with_capacity(stage1.len());
        let mut cursor = 0usize;

        for m in ipv4_re.find_iter(&stage1) {
            if let Ok(ip) = Ipv4Addr::from_str(m.as_str())
                && let Some(orig_ip) = fpe_decrypt_ipv4_192_168(fpe_key, ip)
            {
                if m.start() > cursor {
                    final_buf.push_str(&stage1[cursor..m.start()]);
                }
                final_buf.push_str(&orig_ip.to_string());
                restored_count += 1;
                cursor = m.end();
            }
        }
        if cursor < stage1.len() {
            final_buf.push_str(&stage1[cursor..]);
        }

        Ok(UnweaveOutcome {
            restored_text: final_buf,
            restored_count,
        })
    }

    fn synthesize_and_record(&self, category: EntityCategory, real: &str) -> Result<String> {
        let cat_code = category.as_str();
        if let Some(existing) = self.store.lookup_synthetic_by_real(cat_code, real)? {
            return Ok(existing);
        }

        let subkeys = self.store.subkeys();
        let candidate = match category {
            EntityCategory::CustomDict => {
                let tag = deterministic_token_hex(&subkeys.mac_key, "DICT", real, 8);
                format!("alias_{tag}")
            }
            EntityCategory::ApiKey => {
                let tag = deterministic_token_hex(&subkeys.mac_key, "KEY", real, 16);
                format!("LOOM_SYN_KEY_{tag}")
            }
            EntityCategory::Jwt => {
                let tag = deterministic_token_hex(&subkeys.mac_key, "JWT", real, 20);
                format!("eyJ0eXAiOiJMT09NIn0.eyJzeW4iOiI{tag}In0.sig_{tag}")
            }
            EntityCategory::Email => {
                let (user_part, domain_part) =
                    real.split_once('@').unwrap_or((real, "example.com"));
                let user_tag = deterministic_token_hex(&subkeys.mac_key, "MAIL_USER", user_part, 8);
                let syn_domain = if let Ok(ip) = Ipv4Addr::from_str(domain_part) {
                    self.synthesize_ipv4(ip)
                } else {
                    "example.com".to_string()
                };
                format!("id_{user_tag}@{syn_domain}")
            }
            EntityCategory::UserPath => {
                let tag = deterministic_token_hex(&subkeys.mac_key, "PATH", real, 8);
                if real.contains('\\') {
                    let prefix = &real[..2]; // e.g., "C:"
                    format!("{prefix}\\Users\\user_{tag}")
                } else if real.starts_with("/Users/") {
                    format!("/Users/user_{tag}")
                } else {
                    format!("/home/user_{tag}")
                }
            }
            EntityCategory::Uuid => {
                if let Ok(u) = Uuid::from_str(real) {
                    fpe_encrypt_uuid(&subkeys.fpe_key, u).to_string()
                } else {
                    let tag = deterministic_token_hex(&subkeys.mac_key, "UUID", real, 12);
                    format!("00000000-0000-4000-8000-{tag}")
                }
            }
            EntityCategory::Ipv4 => {
                if let Ok(ip) = Ipv4Addr::from_str(real) {
                    self.synthesize_ipv4(ip)
                } else {
                    "198.51.100.250".to_string()
                }
            }
        };

        self.store.get_or_insert_mapping(cat_code, real, &candidate)
    }

    fn synthesize_ipv4(&self, ip: Ipv4Addr) -> String {
        let subkeys = self.store.subkeys();
        if let Some(fpe_ip) = fpe_encrypt_ipv4_192_168(&subkeys.fpe_key, ip) {
            return fpe_ip.to_string();
        }
        let o = ip.octets();
        let host16 = ((o[2] as u16) << 8) ^ (o[3] as u16) ^ ((o[0] as u16) << 4) ^ (o[1] as u16);
        let perm = feistel16_encrypt(&subkeys.fpe_key, b"loom-ipv4-other", host16);
        // Map into RFC 5737 TEST-NET-2 (198.51.100.1..254) or TEST-NET-3 (203.0.113.1..254)
        let last_octet = ((perm & 0xFF) as u8).clamp(1, 254);
        if (perm >> 8) & 1 == 0 {
            format!("198.51.100.{last_octet}")
        } else {
            format!("203.0.113.{last_octet}")
        }
    }
}
