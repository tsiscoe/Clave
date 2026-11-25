//! Git-aware directory scanner (`loom audit`) and repository scrubber (`loom weave --dir`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ignore::WalkBuilder;
use serde::Serialize;

use crate::detector::LoomDetector;
use crate::engine::LoomEngine;

/// Maximum file size scanned or woven in-place (16 MiB) to prevent OOM DoS (`[SEC-03]` / `CWE-400`).
pub const MAX_SCAN_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// A single sensitive finding discovered during `loom audit`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub file_path: String,
    pub line_number: usize,
    pub category: String,
    pub snippet: String,
}

/// Summary report returned by [`audit_directory`].
#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub root_dir: String,
    pub files_scanned: usize,
    pub findings: Vec<AuditFinding>,
}

/// Canonicalize `root_dir` and confirm `candidate` resides inside `canonical_root`
/// to prevent symlink/junction traversal escapes (`CWE-59`).
pub fn ensure_canonical_containment(canonical_root: &Path, candidate: &Path) -> Result<PathBuf> {
    let canonical_cand = std::fs::canonicalize(candidate).with_context(|| {
        format!(
            "failed to canonicalize candidate path {}",
            candidate.display()
        )
    })?;
    if !canonical_cand.starts_with(canonical_root) {
        return Err(anyhow!(
            "Security violation: symlink/junction escape detected ({} is outside {})",
            canonical_cand.display(),
            canonical_root.display()
        ));
    }
    Ok(canonical_cand)
}

/// Recursively audit a directory or repository (respecting `.gitignore`) for any sensitive
/// IPs, emails, API keys, user paths, UUIDs, or custom dictionary terms.
pub fn audit_directory(root_dir: &Path, detector: &LoomDetector) -> Result<AuditReport> {
    let canonical_root = std::fs::canonicalize(root_dir)
        .with_context(|| format!("failed to canonicalize root dir {}", root_dir.display()))?;

    let mut files_scanned = 0usize;
    let mut findings = Vec::new();

    let walker = WalkBuilder::new(&canonical_root)
        .hidden(false)
        .git_ignore(true)
        .follow_links(false)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Skip `.git/` internal objects and binary/SQLite files
        if path.components().any(|c| c.as_os_str() == ".git") || is_skipped_extension(path) {
            continue;
        }

        let canonical_file = ensure_canonical_containment(&canonical_root, path)?;
        if let Ok(meta) = std::fs::metadata(&canonical_file)
            && meta.len() > MAX_SCAN_FILE_BYTES
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&canonical_file) else {
            continue; // Skip non-UTF8 binary files
        };

        files_scanned += 1;
        let rel_display = canonical_file
            .strip_prefix(&canonical_root)
            .unwrap_or(&canonical_file)
            .display()
            .to_string();

        let spans = detector.detect_spans(&content);
        for span in spans {
            let line_number = 1 + content[..span.start]
                .bytes()
                .filter(|&b| b == b'\n')
                .count();
            let first_line = span.matched_text.lines().next().unwrap_or("");
            let snippet = if span.matched_text.contains('\n') {
                format!("{first_line} ... [multiline]")
            } else {
                first_line.to_string()
            };
            findings.push(AuditFinding {
                file_path: rel_display.clone(),
                line_number,
                category: span.category.as_str().to_string(),
                snippet,
            });
        }
    }

    Ok(AuditReport {
        root_dir: canonical_root.display().to_string(),
        files_scanned,
        findings,
    })
}

/// Recursively weave all UTF-8 text files in `root_dir` in-place (with canonical containment).
pub fn weave_directory_in_place(
    root_dir: &Path,
    engine: &LoomEngine<'_>,
) -> Result<(usize, usize)> {
    let canonical_root = std::fs::canonicalize(root_dir)
        .with_context(|| format!("failed to canonicalize root dir {}", root_dir.display()))?;

    let mut files_modified = 0usize;
    let mut total_replacements = 0usize;

    let walker = WalkBuilder::new(&canonical_root)
        .hidden(false)
        .git_ignore(true)
        .follow_links(false)
        .build();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file()
            || path.components().any(|c| c.as_os_str() == ".git")
            || is_skipped_extension(path)
        {
            continue;
        }
        let canonical_file = ensure_canonical_containment(&canonical_root, path)?;
        if let Ok(meta) = std::fs::metadata(&canonical_file)
            && meta.len() > MAX_SCAN_FILE_BYTES
        {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&canonical_file) else {
            continue;
        };

        let outcome = engine.weave_text(&content)?;
        if outcome.replacements_count > 0 {
            // [SEC-03 / CLAVE-HORDE-04]: Per-file CSPRNG NamedTempFile in parent directory prevents
            // same-stem `.loom_atomic_tmp` collisions and cleans up automatically on interrupted writes.
            let parent_dir = canonical_file.parent().unwrap_or(&canonical_root);
            let mut tmp = tempfile::Builder::new()
                .prefix(".clave_atomic_")
                .suffix(".loom_tmp")
                .tempfile_in(parent_dir)
                .with_context(|| {
                    format!("failed to create atomic temp file in {}", parent_dir.display())
                })?;
            if let Ok(orig_meta) = std::fs::metadata(&canonical_file) {
                let _ = tmp.as_file().set_permissions(orig_meta.permissions());
            }
            std::io::Write::write_all(&mut tmp, outcome.woven_text.as_bytes())?;
            tmp.as_file().sync_all()?;
            tmp.persist(&canonical_file).map_err(|e| e.error)?;
            files_modified += 1;
            total_replacements += outcome.replacements_count;
        }
    }

    Ok((files_modified, total_replacements))
}

fn is_skipped_extension(path: &Path) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "db" | "sqlite"
            | "sqlite3"
            | "wal"
            | "shm"
            | "loom_tmp"
            | "loom_atomic_tmp"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "ico"
            | "pdf"
            | "zip"
            | "tar"
            | "gz"
            | "rlib"
            | "rmeta"
            | "lock"
    )
}
