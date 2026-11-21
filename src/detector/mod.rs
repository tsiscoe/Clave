//! Multi-pattern span detector combining SIMD `Aho-Corasick` custom dictionaries with
//! zero-backtracking `regex` DFA recognizers.

pub mod patterns;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use patterns::{
    EntityCategory, compiled_patterns, should_scrub_email, should_scrub_ipv4,
    should_scrub_user_path, should_scrub_uuid,
};

/// A non-overlapping sensitive span detected in an input text buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedSpan {
    pub start: usize,
    pub end: usize,
    pub category: EntityCategory,
    pub matched_text: String,
}

/// Hybrid SIMD `Aho-Corasick` + Regex DFA detector.
pub struct LoomDetector {
    custom_ac: Option<AhoCorasick>,
}

impl LoomDetector {
    /// Construct a detector with the provided custom dictionary terms (e.g., hostnames, codenames).
    pub fn new(mut custom_terms: Vec<String>) -> Self {
        custom_terms.retain(|t| !t.trim().is_empty());
        // Sort longest first so Aho-Corasick LeftmostLongest prefers longer multi-word phrases
        custom_terms.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        custom_terms.dedup();

        let custom_ac = if custom_terms.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostLongest)
                .ascii_case_insensitive(true)
                .build(&custom_terms)
                .ok()
        };

        Self { custom_ac }
    }

    /// Scan `text` and return a sorted, non-overlapping list of [`DetectedSpan`] hits.
    pub fn detect_spans(&self, text: &str) -> Vec<DetectedSpan> {
        let mut candidates = Vec::new();

        // 1. Custom dictionary hits via SIMD Aho-Corasick
        if let Some(ac) = &self.custom_ac {
            for m in ac.find_iter(text) {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::CustomDict,
                    matched_text: text[m.start()..m.end()].to_string(),
                });
            }
        }

        let pat = compiled_patterns();

        // 2. API Keys
        for m in pat.api_key.find_iter(text) {
            if !m.as_str().starts_with("LOOM_SYN_KEY_") {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::ApiKey,
                    matched_text: m.as_str().to_string(),
                });
            }
        }

        // 3. JWTs
        for m in pat.jwt.find_iter(text) {
            candidates.push(DetectedSpan {
                start: m.start(),
                end: m.end(),
                category: EntityCategory::Jwt,
                matched_text: m.as_str().to_string(),
            });
        }

        // 4. Emails and user@ipv4
        for m in pat.email.find_iter(text) {
            if should_scrub_email(m.as_str()) {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::Email,
                    matched_text: m.as_str().to_string(),
                });
            }
        }

        // 5. OS User Paths
        for m in pat.user_path.find_iter(text) {
            if should_scrub_user_path(m.as_str()) {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::UserPath,
                    matched_text: m.as_str().to_string(),
                });
            }
        }

        // 6. UUIDs
        for m in pat.uuid.find_iter(text) {
            if should_scrub_uuid(m.as_str()) {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::Uuid,
                    matched_text: m.as_str().to_string(),
                });
            }
        }

        // 7. IPv4 addresses
        for m in pat.ipv4.find_iter(text) {
            if should_scrub_ipv4(m.as_str()).is_some() {
                candidates.push(DetectedSpan {
                    start: m.start(),
                    end: m.end(),
                    category: EntityCategory::Ipv4,
                    matched_text: m.as_str().to_string(),
                });
            }
        }

        resolve_non_overlapping(candidates)
    }
}

/// Resolve overlapping candidate spans by preferring:
/// 1. Earlier start offset, or if overlapping:
/// 2. Longer span length, or if equal length:
/// 3. Higher category priority (e.g. `Email` `operator@192.0.2.10` wins over sub-span `192.0.2.10`).
fn resolve_non_overlapping(mut candidates: Vec<DetectedSpan>) -> Vec<DetectedSpan> {
    candidates.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
            .then_with(|| a.category.priority().cmp(&b.category.priority()))
    });

    let mut accepted: Vec<DetectedSpan> = Vec::with_capacity(candidates.len());
    for cand in candidates {
        if let Some(last) = accepted.last()
            && cand.start < last.end
        {
            continue;
        }
        accepted.push(cand);
    }
    accepted
}
