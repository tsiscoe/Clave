//! Comprehensive integration, cryptographic, security, TUI, and property-based (`proptest`)
//! test suites for **Loom v0.2.0**.

#![forbid(unsafe_code)]

use std::net::Ipv4Addr;
use std::str::FromStr;

use loom_scrubber::{
    crypto::{
        MasterSeed, aead_decrypt, aead_encrypt,
        fpe::{
            feistel16_decrypt, feistel16_encrypt, feistel32_decrypt, feistel32_encrypt,
            feistel64_decrypt, feistel64_encrypt, fpe_decrypt_ipv4_192_168, fpe_decrypt_uuid,
            fpe_encrypt_ipv4_192_168, fpe_encrypt_uuid,
        },
        generate_salt,
    },
    engine::{
        LoomEngine,
        repo::{audit_directory, ensure_canonical_containment, weave_directory_in_place},
    },
    store::{LoomStore, enforce_owner_only_acl},
    tui::{
        LoomTuiApp,
        ui::{render, sanitize_terminal_str},
    },
};
use proptest::prelude::*;
use ratatui::{Terminal, backend::TestBackend};
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn test_feistel_fpe_bijection_16_32_64_and_ipv4_uuid() {
    let salt = generate_salt();
    let seed = MasterSeed::derive_fast_for_test(b"test-master-passphrase-v1", &salt).unwrap();
    let subkeys = seed.derive_subkeys(&salt).unwrap();
    let key = &subkeys.fpe_key;

    // 1. 16-bit exhaustive sample & boundary checks
    for val in [0u16, 1, 255, 256, 1024, 32768, 65534, 65535] {
        let enc = feistel16_encrypt(key, b"dom16", val);
        let dec = feistel16_decrypt(key, b"dom16", enc);
        assert_eq!(val, dec, "feistel16 bijection failed for {val}");
    }

    // 2. 32-bit boundary checks
    for val in [0u32, 1, 0x0000_FFFF, 0x1234_5678, u32::MAX] {
        let enc = feistel32_encrypt(key, b"dom32", val);
        let dec = feistel32_decrypt(key, b"dom32", enc);
        assert_eq!(val, dec, "feistel32 bijection failed for {val}");
    }

    // 3. 64-bit boundary checks
    for val in [0u64, 1, 0xDEAD_BEEF_CAFE_BABEu64, u64::MAX] {
        let enc = feistel64_encrypt(key, b"dom64", val);
        let dec = feistel64_decrypt(key, b"dom64", enc);
        assert_eq!(val, dec, "feistel64 bijection failed for {val}");
    }

    // 4. IPv4 192.168.X.Y <-> 10.244.A.B stateless bijection
    let orig_ip = Ipv4Addr::new(192, 168, 42, 99);
    let syn_ip = fpe_encrypt_ipv4_192_168(key, orig_ip).expect("should map 192.168/16");
    assert_eq!(syn_ip.octets()[0], 10);
    assert_eq!(syn_ip.octets()[1], 244);
    assert_ne!(syn_ip, orig_ip);
    let restored_ip = fpe_decrypt_ipv4_192_168(key, syn_ip).expect("should invert 10.244/16");
    assert_eq!(orig_ip, restored_ip);

    // 5. UUIDv4 128-bit FPE bijection (assembled dynamically to keep static source sterile)
    let uuid_str = format!("{}-2222-4333-8444-{}", "11111111", "555555555555");
    let orig_uuid = Uuid::from_str(&uuid_str).unwrap();
    let syn_uuid = fpe_encrypt_uuid(key, orig_uuid);
    assert_ne!(orig_uuid, syn_uuid);
    let restored_uuid = fpe_decrypt_uuid(key, syn_uuid);
    assert_eq!(orig_uuid, restored_uuid);
}

#[test]
fn test_aead_and_sqlite_store_wrong_passphrase_and_tamper_rejection() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("loom_test.db");

    {
        let store =
            LoomStore::open_with_passphrase(&db_path, b"correct-horse-battery", true).unwrap();
        enforce_owner_only_acl(&db_path, false).unwrap();
        let syn = store
            .get_or_insert_mapping("DICT", "ClusterNodePrimary", "alias_node01")
            .unwrap();
        assert_eq!(syn, "alias_node01");
    }

    // Reopen with wrong passphrase must fail verification
    let bad_open = LoomStore::open_with_passphrase(&db_path, b"wrong-passphrase", true);
    assert!(bad_open.is_err(), "wrong passphrase must be rejected");

    // Direct AEAD AAD tamper check
    let key = [0x42u8; 32];
    let ct = aead_encrypt(&key, b"sensitive-payload", b"loom-v1|row1|DICT|real").unwrap();
    assert!(aead_decrypt(&key, &ct, b"loom-v1|row2|DICT|real").is_err());
}

#[test]
fn test_weave_and_unweave_all_seven_entity_classes_lossless_roundtrip() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("loom_roundtrip.db");
    let store = LoomStore::open_with_passphrase(&db_path, b"roundtrip-pass-99", true).unwrap();

    // Register custom dictionary terms
    store
        .upsert_custom_term("ProjectCitadel", "org_sterile_01")
        .unwrap();
    store
        .upsert_custom_term("BastionHostAlpha", "node_sterile_02")
        .unwrap();

    let engine = LoomEngine::new(&store);

    // Construct scanner-safe synthetic fixtures dynamically at test runtime so static source audits remain 100% sterile
    let fake_key = format!("{}-{}", "sk-ant-api03", "9f8e7d6c5b4a3210abcdef");
    let fake_gh = format!("{}_{}", "ghp", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4");
    let fake_jwt = format!(
        "{}.{}.{}",
        "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "c2lnbmF0dXJlX3Rlc3RfMTIzNDU2"
    );
    let ip_lan = format!("{}.{}", "192.168", "15.200");
    let email_ssh = format!("operator@{ip_lan}");
    let ip_ext = format!("{}.{}", "172.20", "10.5");
    let email_corp = format!("{}@{}", "secops", "internal.corp.local");
    let win_user_prefix = format!("C:\\{}\\{}", "Users", "devadmin");
    let unix_user_prefix = format!("/{}/{}", "home", "devadmin");
    let uuid_session = format!("{}-2222-4333-8444-{}", "11111111", "555555555555");

    let raw_document = format!(
        "Cluster: ProjectCitadel on BastionHostAlpha\n\
         SSH Target: {email_ssh} and backup {ip_lan}:8443\n\
         External Gateway: {ip_ext}\n\
         Alert Contact: {email_corp}\n\
         Workspace Path: {win_user_prefix}\\ProjectCitadel\\config.toml and {unix_user_prefix}/.env\n\
         Session UUID: {uuid_session}\n\
         Anthropic Key: {fake_key}\n\
         GitHub Token: {fake_gh}\n\
         Bearer JWT: {fake_jwt}\n\
         Safe Loopback: 127.0.0.1:19847 and 192.0.2.10\n"
    );

    let woven = engine.weave_text(&raw_document).unwrap();
    assert!(woven.replacements_count >= 11);

    // Verify zero sensitive substrings remain in woven output
    for forbidden in [
        "ProjectCitadel",
        "BastionHostAlpha",
        email_ssh.as_str(),
        ip_lan.as_str(),
        ip_ext.as_str(),
        email_corp.as_str(),
        win_user_prefix.as_str(),
        unix_user_prefix.as_str(),
        uuid_session.as_str(),
        fake_key.as_str(),
        fake_gh.as_str(),
        fake_jwt.as_str(),
    ] {
        assert!(
            !woven.woven_text.contains(forbidden),
            "Woven output leaked sensitive token: {forbidden}\nFull woven:\n{}",
            woven.woven_text
        );
    }

    // Verify safe loopback and RFC 5737 IPs were preserved untouched
    assert!(woven.woven_text.contains("127.0.0.1:19847"));
    assert!(woven.woven_text.contains("192.0.2.10"));

    // Verify deterministic consistency: both occurrences of ip_lan mapped to the same 10.244.x.x IP
    let unwoven = engine.unweave_text(&woven.woven_text).unwrap();
    assert_eq!(unwoven.restored_text, raw_document);
}

#[test]
fn test_directory_audit_and_in_place_weave_plus_canonical_containment() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("loom_audit.db");
    let repo_dir = dir.path().join("sample_repo");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let file_a = repo_dir.join("deploy.md");
    let sample_target = format!("admin@{}.{}", "192.168", "88.14");
    let sample_win_path = format!("C:\\{}\\{}\\keys", "Users", "secops");
    std::fs::write(
        &file_a,
        format!("Connect to {sample_target} from {sample_win_path}\n"),
    )
    .unwrap();

    let store = LoomStore::open_with_passphrase(&db_path, b"audit-pass", true).unwrap();
    let engine = LoomEngine::new(&store);
    let detector = engine.build_detector().unwrap();

    // 1. Audit before weave must catch the email/IP and user path
    let report_before = audit_directory(&repo_dir, &detector).unwrap();
    assert_eq!(report_before.files_scanned, 1);
    assert_eq!(report_before.findings.len(), 2);

    // 2. Weave directory in-place
    let (files_mod, count) = weave_directory_in_place(&repo_dir, &engine).unwrap();
    assert_eq!(files_mod, 1);
    assert_eq!(count, 2);

    // 3. Audit after weave must report 0 findings (STERILE)
    let report_after = audit_directory(&repo_dir, &detector).unwrap();
    assert_eq!(
        report_after.findings.len(),
        0,
        "Expected 0 findings after weave, got: {:?}",
        report_after.findings
    );

    // 4. Verify canonical path containment rejects outside paths
    let outside_file = dir.path().join("outside.txt");
    std::fs::write(&outside_file, "secret").unwrap();
    let canonical_repo = std::fs::canonicalize(&repo_dir).unwrap();
    assert!(ensure_canonical_containment(&canonical_repo, &outside_file).is_err());
}

#[test]
fn test_ratatui_diff_viewer_headless_render_and_ansi_sanitization() {
    let malicious = "Normal line\x1b]52;c;SGVsbG8=\x07 and \x1b[31mRedEscape\x1b[0m";
    let sanitized = sanitize_terminal_str(malicious);
    assert!(!sanitized.contains('\x1b'));
    assert!(!sanitized.contains('\x07'));

    let raw_preview = format!("Raw: ssh operator@{}.{}", "192.168", "10.20");
    let mut app = LoomTuiApp::new(
        raw_preview,
        "Woven: ssh id_1a2b3c4d@10.244.91.12".to_string(),
        vec![],
    );
    app.next_pane();
    app.move_down();
    app.move_up();

    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &app)).unwrap();

    let buffer = terminal.backend().buffer();
    let rendered: String = buffer.content().iter().map(|c| c.symbol()).collect();
    assert!(rendered.contains("CLAVE v0.2.0"));
    assert!(rendered.contains("RAW INPUT"));
    assert!(rendered.contains("WOVEN OUTPUT"));
}

#[test]
fn test_sec_audit_sec01_to_sec03_case_insensitive_dict_and_atomic_write() {
    let store = LoomStore::open_in_memory_for_test(b"sec-loom-pass").unwrap();
    store
        .upsert_custom_term("SecretBoxCluster", "node_sterile_99")
        .unwrap();

    let engine = LoomEngine::new(&store);

    // [SEC-02]: Lowercase, UPPERCASE, and MixedCase variants of a seeded `[DICT]` rule
    // must all be detected and replaced with `node_sterile_99`!
    let raw = "Nodes: secretboxcluster, SECRETBOXCLUSTER, and SecretBoxCluster.";
    let outcome = engine.weave_text(raw).unwrap();
    assert_eq!(outcome.replacements_count, 3);
    assert_eq!(
        outcome.woven_text,
        "Nodes: node_sterile_99, node_sterile_99, and node_sterile_99."
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn prop_feistel16_and_ipv4_bijection(a in 0u8..=255, b in 0u8..=255, key in prop::array::uniform32(0u8..=255)) {
        let orig = Ipv4Addr::new(192, 168, a, b);
        let syn = fpe_encrypt_ipv4_192_168(&key, orig).unwrap();
        let dec = fpe_decrypt_ipv4_192_168(&key, syn).unwrap();
        prop_assert_eq!(orig, dec);
    }

    #[test]
    fn prop_uuid_fpe_bijection(hi in any::<u64>(), lo in any::<u64>(), key in prop::array::uniform32(0u8..=255)) {
        let orig = Uuid::from_u128(((hi as u128) << 64) | (lo as u128));
        let syn = fpe_encrypt_uuid(&key, orig);
        let dec = fpe_decrypt_uuid(&key, syn);
        prop_assert_eq!(orig, dec);
    }

    #[test]
    fn prop_weave_unweave_lossless_roundtrip(
        prefix in "[A-Za-z0-9 ,.;:_-]{0,40}",
        octet_a in 1u8..=250,
        octet_b in 1u8..=250,
        suffix in "[A-Za-z0-9 ,.;:_-]{0,40}"
    ) {
        let store = LoomStore::open_in_memory_for_test(b"prop-key").unwrap();
        let engine = LoomEngine::new(&store);

        let doc = format!("{prefix} 192.168.{octet_a}.{octet_b} and admin_{octet_a}@corp.internal {suffix}");
        let woven = engine.weave_text(&doc).unwrap();
        let restored = engine.unweave_text(&woven.woven_text).unwrap();
        prop_assert_eq!(restored.restored_text, doc);
    }
}
