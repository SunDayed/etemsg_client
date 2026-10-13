# msg-client-rust

[简体中文](README_CN.md)

A Rust terminal UI client for the `etemsg` end-to-end encrypted chat service. It manages local identities, encrypts 1v1 messages and files, and uses OpenMLS for group encryption. The server only relays ciphertext and opaque MLS objects.

## Features

- RSA-4096 identities and challenge-response login.
- End-to-end encrypted 1v1 text messages with AES-256-GCM, RSA-OAEP key wrapping, and message signatures.
- Streaming, resumable encrypted file transfer for 1v1 chats.
- MLS (RFC 9420) groups: create, join, approve, message sync, rename, leave, kick, transfer, and dissolve.
- Multi-server support with independent identity, contacts, and local data per server.
- SQLCipher-encrypted local database.
- Keyboard-driven TUI built with ratatui and crossterm.
- REST certificate SPKI pinning (TOFU) and automatic WebSocket reconnect.

## Build

Requirements: Rust 1.91+ and Cargo.

```bash
cd client

# Recommended: build and update dist/msg-client-rust
./build.sh

# Or build directly
cargo build --release --offline
```

The release binary is written to `target/release/msg-client-rust`; `./build.sh` copies it to `dist/msg-client-rust`.

Run tests:

```bash
cargo test --release --offline
```
