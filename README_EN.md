# msg-client-rust — End-to-End Encrypted Chat Client

`msg-client-rust` is a terminal TUI instant-messaging client written in Rust. It is the client for the `etemsg` Go relay: it generates and stores identity keys, encrypts 1v1 messages end-to-end, streams and encrypts files, and uses OpenMLS to manage group end-to-end encryption. The server stores and forwards ciphertext and opaque MLS objects only.

> This README reflects the current source tree. The repository root `README.md` documents the full protocol and flows; `../ASSESSMENT.md` contains the current security, performance and functional assessment.

---

## 1. Highlights

| Capability | Implementation |
|---|---|
| Identity | RSA-4096; private key stored only in the local SQLCipher DB; user ID = `sha512(SPKI-DER).hex()[:10]` |
| 1v1 text | Fresh AES-256-GCM key per message; key wrapped to recipient with RSA-4096 OAEP-SHA256 |
| Message auth | RSA-PKCS1v15-SHA256 signatures; both the server and recipient verify |
| File transfer | Streaming AES-256-GCM in 1 MiB chunks, separately encrypted filename, SHA-256 plaintext check, resumable download |
| Groups | OpenMLS / RFC 9420; the server relays Commit, Welcome and group ciphertext without parsing or decrypting |
| Realtime | WSS with automatic reconnect and a 30-second application heartbeat |
| Offline messages | Pulled after login via `/get_offline_msg`, verified and decrypted one by one |
| Multi-server | Multiple servers, each with an independent identity, contact list and conversation set |
| Local storage | SQLCipher (`bundled-sqlcipher`), partitioned by `server_id` |
| TUI | ratatui + crossterm, keyboard-first, no mouse required |
| Certificate policy | REST pins the SPKI SHA-256 (TOFU); WSS currently does **not** validate the server certificate |

---

## 2. Technology Stack

- Rust 2021, `rust-version = "1.91"` (`Cargo.toml`)
- UI: `ratatui 0.30` + `crossterm 0.29`
- Crypto: `rsa 0.9`, `aes-gcm 0.10`, `sha2`, `md-5`
- Groups: `openmls 0.9` + `openmls_rust_crypto`
- Storage: `rusqlite 0.37` with `bundled-sqlcipher`
- Network: `rustls 0.23` + `ring`, a small hand-written HTTP/1.1 client, and `tungstenite` for WebSocket

---

## 3. Source Layout

```text
client/
├── Cargo.toml / Cargo.lock
├── build.sh                    builds and updates only dist/msg-client-rust
├── dist/                       runtime directory (never overwritten by build.sh)
└── src/
    ├── main.rs                 CLI, master-key unlock, diagnostics, bootstrap
    ├── core.rs                 login, WS I/O, encryption, file transfer, reconnect
    ├── ui.rs                   TUI layout, session tree, modals, key handling
    ├── store.rs                SQLCipher schema and queries
    ├── crypto.rs               RSA/AES/signatures/IDs/streaming file crypto
    ├── log.rs                  file logger that avoids corrupting the TUI
    ├── group_cli.rs            headless group subcommands
    ├── net/
    │   ├── tls.rs              rustls + SPKI TOFU verifier
    │   ├── http.rs             minimal HTTPS/1.1 client
    │   └── ws.rs               WebSocket client
    └── group/
        ├── adapter.rs          OpenMLS state-machine wrapper
        ├── service.rs          group use-case orchestration
        ├── runtime.rs          background group sync worker
        ├── net_transport.rs    signed group REST transport
        ├── storage.rs          local group tables
        └── state.rs            group role/state data types
```

---

## 4. Build

```bash
cd client

# Option 1: script; updates dist/msg-client-rust
./build.sh

# Option 2: direct Cargo build
cargo build --release --offline
# output: target/release/msg-client-rust
```

`build.sh` deliberately updates **only the binary** in `dist/`. It never copies, creates or overwrites runtime state such as `etemsg.db`, `etemsg.db-wal`, `etemsg.db-shm`, logs, or `received_files/`.

Run the tests:

```bash
cargo test --release --offline
```

---

## 5. Running and Configuration

```bash
# Default: etemsg.db next to the executable; first run asks for a master key
dist/msg-client-rust

# Use a specific database
dist/msg-client-rust --db /path/to/etemsg.db

# Supply the master key directly (warning: visible in the process list)
dist/msg-client-rust --key 'your-strong-master-key'
```

Resolution order:

- Database: `--db` → `MSG_CLIENT_DB` → `etemsg.db` next to the executable → `etemsg.db` in the current directory
- Master key: `--key` → `MSG_CLIENT_KEY` → interactive prompt

The master key is the only protection for the local SQLCipher database, which contains plaintext chat history, MLS private state and RSA private keys. Use a strong random passphrase or an OS keyring.

---

## 6. TUI Keys

| Key | Action |
|---|---|
| `F1` | Server configuration: add, delete, rename, connect |
| `F2` | Add contact (can extract an ID from pasted text) |
| `F3` | Send file (1v1 only; group files are unsupported) |
| `F4` | Help |
| `F5` | Create group (name and nickname required) |
| `F6` | Request to join a group (group ID, note and nickname required) |
| `F7` | Notification center: group approvals, ownership transfers, friend requests |
| `F8` | Manual group sync |
| `F9` | View group members; owner can remove a member |
| `r` | Rename server/contact/group (group rename is owner-only) |
| `d` | Delete contact; when a group is selected, leave the group |
| `t` | Transfer group ownership (owner only) |
| `D` | Dissolve group (owner only) |
| `Enter` | Open/send/confirm |
| `Tab` | Toggle focus between session tree and input box |
| `Ctrl+J` or `Shift+Enter` | New line in the input box |
| `Ctrl+Alt+M` / `Alt+M` | Exit (performs a WAL checkpoint first) |
| `Ctrl+C` / `Ctrl+Q` | Intentionally ignored to avoid accidental exit |

---

## 7. Diagnostics and Group CLI

The product is the TUI, but the same binary exposes headless commands for diagnostics and automation:

```bash
dist/msg-client-rust --selftest <db> <key>
dist/msg-client-rust --nettest  <db> <key>
dist/msg-client-rust --wstest   <db> <key>
dist/msg-client-rust --keytest

# Headless group operations
dist/msg-client-rust --db <db> --key <key> --group-list
dist/msg-client-rust --db <db> --key <key> --group-create "Name" "My nickname"
dist/msg-client-rust --db <db> --key <key> --group-request <gid> "Note" "My nickname"
dist/msg-client-rust --db <db> --key <key> --group-sync <gid>
```

See the root `README.md` for the full command list, or run `dist/msg-client-rust --help`.

---

## 8. Security Model

- **Transport**: REST pins the server certificate SPKI SHA-256 with TOFU; WSS does not currently validate the certificate.
- **Identity**: RSA-4096 private keys stay in the encrypted local DB; registration and contact discovery verify `public_key_id(pub) == user_id`.
- **1v1 messages**: AES-256-GCM content encryption, RSA-OAEP key wrapping, RSA-PKCS1v15-SHA256 signatures.
- **Files**: chunked AES-256-GCM with `AAD = file_id|size`, per-chunk IVs derived from a random base IV, and SHA-256 verification of the decrypted plaintext.
- **Groups**: MLS state and membership changes are performed by member clients; the server never parses, generates or decrypts MLS objects.
- **Local data**: the master key is supplied only at runtime and is never embedded; the client checkpoints WAL before exit so a file-level backup of `etemsg.db` is consistent.

### Current security caveats

1. `--key` appears in the process list; prefer the interactive prompt or `MSG_CLIENT_KEY`, and protect the environment.
2. WSS does not pin or validate the server certificate. A network attacker can observe connection metadata and forge realtime control frames; application-layer signatures still protect message content and origin.
3. The strength of the local master key determines the safety of all local history, RSA keys and MLS state.
4. On some systems, the database, logs and received plaintext files may be created with umask-dependent permissions; restrict them to the current user in deployment.

---

## 9. Tests

```bash
cargo test --release --offline
```

The current test suite covers SQLCipher, protocol digests, file crypto, UI key handling and group join/leave/rename/transfer/kick scenarios. At the time this README was generated, all 82 tests passed.

---

## 10. Known Boundaries

- Group file transfer is not implemented; files are 1v1 only.
- WSS has no certificate pinning; only REST performs SPKI TOFU.
- Group operations (create/join/approve/rename/kick/leave/transfer/dissolve) run on background threads, so the TUI no longer blocks on network or MLS round-trips; results arrive as toasts/notices.
- No multi-device support: one identity and one WS connection per user per server.
- Neither client nor server performs automatic schema migration; verify compatibility before upgrading.
- KeyPackages are not single-use; the server relays group notifications opaquely and membership authority lives in the MLS ratchet tree.
- If the owner starts a transfer and leaves while the designee neither accepts nor declines, the group stays in an owner-vacant "dead state" (joins/approvals are blocked, messaging still works); there is no automatic timeout or fallback.

---

## 11. Related Documents

- Repository root: `../README.md`
- Project assessment: `../ASSESSMENT.md`
- Server documentation: `../server/README.md`
