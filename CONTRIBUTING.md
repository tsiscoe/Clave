# Contributing to Loom

Thank you for contributing to **Loom**! Because Loom handles cryptographic pseudonymization and sensitive credential scrubbing, all contributions must pass strict safety and verification gates.

## Mandatory Quality Gates

1. **Zero Unsafe Code:** The crate enforces `#![forbid(unsafe_code)]` at the compiler level.
2. **Formatting:** Run `cargo fmt --all -- --check` before submitting a PR.
3. **Zero Clippy Warnings:** Run `cargo clippy --all-targets -- -D warnings`.
4. **Property-Based Roundtrip Proofs:** Every new recognizer or FPE primitive must include a `proptest!` roundtrip proof in `tests/integration_tests.rs` verifying `unweave(weave(x)) == x`.
5. **Sterile Fixtures Only:** Never include real IPs, personal names, or live API keys in tests or documentation. Use RFC 5737 (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and RFC 2606 (`example.com`) addresses exclusively.
