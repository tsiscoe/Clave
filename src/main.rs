//! Entrypoint for the `clave` binary.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use loom_scrubber::{
    cli::{Cli, Commands, DictAction},
    crypto::deterministic_token_hex,
    engine::{
        LoomEngine,
        repo::{audit_directory, weave_directory_in_place},
    },
    store::{LoomStore, default_ledger_path},
    tui::{LoomTuiApp, run_interactive_tui, ui::sanitize_terminal_str},
};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "clave-crypto-scrubber";
const KEYRING_USER: &str = "default-ledger";

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.clone().unwrap_or_else(default_ledger_path);
    let passphrase = resolve_passphrase(&cli)?;

    let store = LoomStore::open_with_passphrase(&db_path, passphrase.as_bytes(), false)?;
    drop(passphrase);
    let engine = LoomEngine::new(&store);

    match cli.command {
        Commands::Weave { input, output, dir } => {
            if let Some(target_dir) = dir {
                let (files_mod, count) = weave_directory_in_place(&target_dir, &engine)?;
                eprintln!(
                    "[clave] Woven {count} sensitive spans across {files_mod} files in {}",
                    target_dir.display()
                );
                return Ok(());
            }

            let raw = read_input_source(input.as_ref())?;
            let outcome = engine.weave_text(&raw)?;
            write_output_sink(output.as_ref(), &outcome.woven_text)?;
            if let Some(out_path) = &output {
                eprintln!(
                    "[clave] Woven {} sensitive spans into {}",
                    outcome.replacements_count,
                    out_path.display()
                );
            }
        }

        Commands::Unweave { input, output } => {
            let woven = read_input_source(input.as_ref())?;
            let outcome = engine.unweave_text(&woven)?;
            write_output_sink(output.as_ref(), &outcome.restored_text)?;
            if let Some(out_path) = &output {
                eprintln!(
                    "[clave] Restored {} synthetic spans into {}",
                    outcome.restored_count,
                    out_path.display()
                );
            }
        }

        Commands::Clip { restore } => {
            let mut cb =
                arboard::Clipboard::new().context("failed to access OS system clipboard")?;
            let current = cb
                .get_text()
                .context("failed to read UTF-8 text from system clipboard")?;
            if restore {
                let outcome = engine.unweave_text(&current)?;
                let restored = Zeroizing::new(outcome.restored_text);
                #[cfg(windows)]
                {
                    use arboard::SetExtWindows;
                    cb.set()
                        .exclude_from_monitoring()
                        .text(restored.as_str())
                        .context("failed to write restored text to clipboard")?;
                }
                #[cfg(target_os = "macos")]
                {
                    use arboard::SetExtApple;
                    cb.set()
                        .exclude_from_history()
                        .text(restored.as_str())
                        .context("failed to write restored text to clipboard")?;
                }
                #[cfg(not(any(windows, target_os = "macos")))]
                {
                    cb.set_text(restored.as_str())
                        .context("failed to write restored text to clipboard")?;
                }
                eprintln!(
                    "[clave] Restored {} synthetic tokens in system clipboard (private mode).",
                    outcome.restored_count
                );
            } else {
                let outcome = engine.weave_text(&current)?;
                cb.set_text(outcome.woven_text)
                    .context("failed to write woven text to clipboard")?;
                eprintln!(
                    "[clave] Woven {} sensitive tokens in system clipboard.",
                    outcome.replacements_count
                );
            }
        }

        Commands::Audit {
            path,
            json,
            fail_on_leak,
        } => {
            let detector = engine.build_detector()?;
            let report = audit_directory(&path, &detector)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "CLAVE AUDIT // Scanned {} files in {}",
                    report.files_scanned, report.root_dir
                );
                if report.findings.is_empty() {
                    println!("STATUS: STERILE (0 sensitive findings detected)");
                } else {
                    println!(
                        "STATUS: {} SENSITIVE FINDINGS DETECTED",
                        report.findings.len()
                    );
                    for f in &report.findings {
                        println!(
                            "  [{:<4}] {}:{} -> {}",
                            sanitize_terminal_str(&f.category),
                            sanitize_terminal_str(&f.file_path),
                            f.line_number,
                            sanitize_terminal_str(&f.snippet)
                        );
                    }
                }
            }
            if fail_on_leak && !report.findings.is_empty() {
                std::process::exit(1);
            }
        }

        Commands::Dict { action } => match action {
            DictAction::Add { term, alias } => {
                let syn = match alias {
                    Some(a) => a,
                    None => {
                        let tag =
                            deterministic_token_hex(&store.subkeys().mac_key, "DICT", &term, 8);
                        format!("alias_{tag}")
                    }
                };
                let saved = store.upsert_custom_term(&term, &syn)?;
                println!("[clave] Registered custom dictionary rule: [REDACTED] <-> {saved}");
            }
            DictAction::List { json, reveal } => {
                let mut mappings = store.list_all_mappings()?;
                if !reveal {
                    for m in &mut mappings {
                        zeroize::Zeroize::zeroize(&mut m.real_value);
                        m.real_value = "[REDACTED — pass --reveal]".to_string();
                    }
                }
                if json {
                    println!("{}", serde_json::to_string_pretty(&mappings)?);
                } else {
                    println!("CLAVE ENCRYPTED LEDGER // {} MAPPINGS", mappings.len());
                    for m in mappings {
                        println!(
                            "  [{:<4}] {:<32} <= [AEAD: {}]",
                            sanitize_terminal_str(&m.category),
                            sanitize_terminal_str(&m.synthetic_value),
                            sanitize_terminal_str(&m.real_value)
                        );
                    }
                }
            }
        },

        Commands::Tui { file } => {
            let raw_text = match file {
                Some(path) => std::fs::read_to_string(&path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
                None => {
                    "Sample Log: ssh deploy@192.0.2.10 with token LOOM_SYN_KEY_demo1234 and path C:\\Users\\Public\\demo.txt"
                        .to_string()
                }
            };
            let outcome = engine.weave_text(&raw_text)?;
            let mappings = store.list_all_mappings()?;
            let app = LoomTuiApp::new(raw_text, outcome.woven_text, mappings);
            run_interactive_tui(app)?;
        }
    }

    Ok(())
}

fn resolve_passphrase(cli: &Cli) -> Result<Zeroizing<String>> {
    if let Some(ref key_file) = cli.passphrase_file {
        let raw = Zeroizing::new(
            std::fs::read_to_string(key_file)
                .with_context(|| format!("failed to read passphrase file {}", key_file.display()))?,
        );
        let trimmed = Zeroizing::new(raw.trim().to_string());
        if trimmed.is_empty() {
            return Err(anyhow!(
                "Passphrase file {} cannot be empty",
                key_file.display()
            ));
        }
        if cli.keyring
            && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        {
            let _ = entry.set_password(trimmed.as_str());
        }
        return Ok(trimmed);
    }

    if let Ok(env_pass) = std::env::var("CLAVE_PASSPHRASE") {
        let wrapped = Zeroizing::new(env_pass);
        if !wrapped.is_empty() {
            if cli.keyring
                && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
            {
                let _ = entry.set_password(wrapped.as_str());
            }
            return Ok(wrapped);
        }
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(saved) = entry.get_password()
    {
        let wrapped = Zeroizing::new(saved);
        if !wrapped.is_empty() {
            return Ok(wrapped);
        }
    }

    let prompt_pass = Zeroizing::new(
        rpassword::prompt_password("Clave Master Passphrase: ")
            .context("failed to read passphrase from terminal")?,
    );
    if prompt_pass.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty"));
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.set_password(prompt_pass.as_str());
    }

    Ok(prompt_pass)
}

fn read_input_source(input: Option<&PathBuf>) -> Result<String> {
    if let Some(path) = input {
        std::fs::read_to_string(path)
            .with_context(|| format!("failed to read input file {}", path.display()))
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read UTF-8 stream from stdin")?;
        Ok(buf)
    }
}

fn write_output_sink(output: Option<&PathBuf>, content: &str) -> Result<()> {
    if let Some(path) = output {
        std::fs::write(path, content)
            .with_context(|| format!("failed to write output file {}", path.display()))
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(content.as_bytes())
            .context("failed to write output stream to stdout")
    }
}
