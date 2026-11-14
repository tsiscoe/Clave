//! Entrypoint for the `loom` binary.

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
    tui::{LoomTuiApp, run_interactive_tui},
};

const KEYRING_SERVICE: &str = "loom-crypto-scrubber";
const KEYRING_USER: &str = "default-ledger";

fn main() -> Result<()> {
    let cli = Cli::parse();
    let db_path = cli.db.clone().unwrap_or_else(default_ledger_path);
    let passphrase = resolve_passphrase(&cli)?;

    let store = LoomStore::open_with_passphrase(&db_path, passphrase.as_bytes(), false)?;
    let engine = LoomEngine::new(&store);

    match cli.command {
        Commands::Weave { input, output, dir } => {
            if let Some(target_dir) = dir {
                let (files_mod, count) = weave_directory_in_place(&target_dir, &engine)?;
                eprintln!(
                    "[loom] Woven {count} sensitive spans across {files_mod} files in {}",
                    target_dir.display()
                );
                return Ok(());
            }

            let raw = read_input_source(input.as_ref())?;
            let outcome = engine.weave_text(&raw)?;
            write_output_sink(output.as_ref(), &outcome.woven_text)?;
            if let Some(out_path) = &output {
                eprintln!(
                    "[loom] Woven {} sensitive spans into {}",
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
                    "[loom] Restored {} synthetic spans into {}",
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
                cb.set_text(outcome.restored_text)
                    .context("failed to write restored text to clipboard")?;
                eprintln!(
                    "[loom] Restored {} synthetic tokens in system clipboard.",
                    outcome.restored_count
                );
            } else {
                let outcome = engine.weave_text(&current)?;
                cb.set_text(outcome.woven_text)
                    .context("failed to write woven text to clipboard")?;
                eprintln!(
                    "[loom] Woven {} sensitive tokens in system clipboard.",
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
                    "LOOM AUDIT // Scanned {} files in {}",
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
                            f.category, f.file_path, f.line_number, f.snippet
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
                println!("[loom] Registered custom dictionary rule: [REDACTED] <-> {saved}");
            }
            DictAction::List { json } => {
                let mappings = store.list_all_mappings()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&mappings)?);
                } else {
                    println!("LOOM ENCRYPTED LEDGER // {} MAPPINGS", mappings.len());
                    for m in mappings {
                        println!(
                            "  [{:<4}] {:<32} <= [AEAD: {}]",
                            m.category, m.synthetic_value, m.real_value
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
                    "Sample Log: ssh deploy@192.168.42.19 with key sk-ant-api03-9f8e7d6c5b4a3210 and path C:\\Users\\alice\\secrets.txt"
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

fn resolve_passphrase(cli: &Cli) -> Result<String> {
    if let Some(p) = &cli.passphrase
        && !p.is_empty()
    {
        if cli.keyring
            && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        {
            let _ = entry.set_password(p);
        }
        return Ok(p.clone());
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        && let Ok(saved) = entry.get_password()
        && !saved.is_empty()
    {
        return Ok(saved);
    }

    let prompt_pass = rpassword::prompt_password("Loom Master Passphrase: ")
        .context("failed to read passphrase from terminal")?;
    if prompt_pass.is_empty() {
        return Err(anyhow!("Passphrase cannot be empty"));
    }

    if cli.keyring
        && let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
    {
        let _ = entry.set_password(&prompt_pass);
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
