# Installing Clave

## Prerequisites

- **Rust Toolchain:** Rust `1.85+` (2024 Edition) via [rustup.rs](https://rustup.rs/)
- **Supported Platforms:**
  - Windows 10 / 11 (`x86_64-pc-windows-msvc`)
  - Linux (`x86_64-unknown-linux-gnu`, uses pure-Rust `linux-keyutils` for keyring support—zero `libdbus` or `libxcb` apt packages required)
  - macOS 13+ (`aarch64-apple-darwin` & `x86_64-apple-darwin`)

---

## Option 1: Install Directly via Cargo

```bash
cargo install --git https://github.com/tsiscoe/Clave.git
```

Verify installation:

```bash
clave --version
```

---

## Option 2: Build from Source

```bash
git clone https://github.com/tsiscoe/Clave.git
cd Clave
cargo build --release
```

The compiled binary will be located at:
- **Windows:** `.\target\release\clave.exe`
- **Linux / macOS:** `./target/release/clave`

---

## Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `CLAVE_PASSPHRASE` | Master passphrase for non-interactive CLI / CI pipelines | Interactive prompt or OS Keyring (`--keyring`) |
| `CLAVE_DB_PATH` | Custom file path for the encrypted SQLite WAL token ledger | `%APPDATA%\loom\loom.db` (Win) or `~/.local/share/loom/loom.db` (Unix) |
