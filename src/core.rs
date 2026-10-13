//! Client core: session management, login, WebSocket I/O and message encryption/decryption. Fully decoupled from the UI.
//! Threading: one login thread + one WebSocket thread per server; results reach the UI over an `mpsc` event channel, and shared state is guarded by `Mutex` / `AtomicBool`.

use crate::crypto;
use crate::net;
use crate::store::{self, Store};
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const FILE_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-file size limit, matching the Go relay's default `MaxFileSize` (500 MiB; the server accepts 1..500 MiB)
const MAX_FILE_BYTES: u64 = 500 * 1024 * 1024;
/// Server `FileNameMax` defaults to 1024 chars; the `filename` we upload is filename_enc
const MAX_FILENAME_ENC_LEN: usize = 1024;
/// Max receive attempts (first try + 2 retries); only after all fail is the file marked "receive failed"
const FILE_RECV_ATTEMPTS: u32 = 3;
const MAX_NICKNAME_CHARS: usize = 32;

#[derive(Debug, Clone)]
pub enum Event {
    ServersChanged,
    /// Per-conversation unread count changed (incremental, so the tree is not rebuilt on every message)
    UnreadChanged { server_id: String, contact: String, unread: i64, delta: i64 },
    Toast(String),
    LoginStatus { text: String },
    /// One login round finished; the UI closes the server dialog only when `ok` and all servers are online
    LoginFinished { ok: bool },
    ChatUpdated { server_id: String, contact: String },
    AddContactResult { req_id: String, ok: bool, message: String },
    /// Someone added me one-way (WS `contact_notify`): the notification center should light up.
    FriendRequest { sid: String, from: String },
    /// Local system notice (group dissolved / removed, etc.), filed under "other messages" in the notification center.
    SystemNotice(String),
    PresenceChanged { server_id: String, contact: String, online: bool },
    PresenceRefreshed { server_id: String },
    /// A group has new data (WS push or local op); the UI rebuilds the group list while a worker pulls and decrypts bodies into the DB.
    GroupDirty { server_id: String, group_id: String },
    /// A group has `count` pending join requests (owners/admins only); besides a toast, the UI persists a marker in the tree because approvals need a human.
    GroupPendingApprovals { server_id: String, group_id: String, count: usize },
    /// A UI-triggered group operation finished on a background thread. The UI correlates it by `id`
    /// so a stale result cannot close a newer modal.
    GroupOpDone { id: u64, op: GroupOp, ok: bool, message: String },
}

/// UI-originated group operations that are executed off the main TUI thread.
#[derive(Debug, Clone)]
pub enum GroupOp {
    CreateGroup,
    JoinGroup,
    RenameGroup,
    LeaveGroup { sid: String, gid: String },
    TransferOwner { sid: String, gid: String, nick: String },
    DissolveGroup { sid: String, gid: String },
    KickMember { sid: String, gid: String, nick: String },
    /// One notice-center action (approve/deny join request or owner transfer).
    Notice,
}

pub enum Outbound {
    Text(String),
    Stop,
}

/// Build a runtime `Session` from a stored server row (shared by `Core::new` and `add_server`), so adding a server cannot drift and silently drop an `Arc`.
fn build_session(store: &Store, s: &store::Server) -> Result<Session> {
    let username = store.get_state(&format!("current_user_{}", s.id))?;
    Ok(Session {
        name: Arc::new(Mutex::new(s.name.clone())),
        host: s.host.clone(),
        // `as u16` silently truncates, so re-clamp here: a hand-edited or corrupted DB would otherwise connect to an unrelated port with no error
        port: s.api_port.clamp(store::PORT_MIN, store::PORT_MAX) as u16,
        state: Arc::new(Mutex::new(SessionState {
            username,
            // A failed unread read must not block startup: fall back to an empty map and log to stderr (the TUI owns the screen, so no toast)
            unread: store.get_unread(&s.id).unwrap_or_else(|e| {
                crate::tui_log!("failed to read the unread count for server {}: {e:#}", s.id);
                Default::default()
            }),
            ..Default::default()
        })),
        ws_connected: Arc::new(AtomicBool::new(false)),
        connecting: Arc::new(AtomicBool::new(false)),
        ws_alive: Arc::new(AtomicBool::new(false)),
        group_runtime: Arc::new(crate::group::runtime::GroupRuntime::default()),
        ws_epoch: Arc::new(AtomicU64::new(0)),
        ever_connected: Arc::new(AtomicBool::new(false)),
        tx: Arc::new(Mutex::new(None)),
    })
}

#[derive(Default)]
pub struct SessionState {
    pub username: Option<String>,
    pub error: Option<String>,
    pub unread: HashMap<String, i64>,
    /// Contacts currently online (per server), from the post-login snapshot and presence pushes — not server connectivity (see `Session::status()`).
    pub online_contacts: HashSet<String>,
}

#[derive(Clone)]
pub struct Session {
    pub name: Arc<Mutex<String>>,
    pub host: String,
    pub port: u16,
    pub state: Arc<Mutex<SessionState>>,
    pub ws_connected: Arc<AtomicBool>,
    /// Set while the login/reconnect supervisor thread runs, preventing duplicate connections to one server
    pub connecting: Arc<AtomicBool>,
    pub group_runtime: Arc<crate::group::runtime::GroupRuntime>,
    /// Whether the current WebSocket thread is alive (the supervisor uses it to decide when to reconnect)
    pub ws_alive: Arc<AtomicBool>,
    /// WebSocket generation counter, so an old thread exiting cannot clear the new connection's alive flag
    pub ws_epoch: Arc<AtomicU64>,
    /// Ever authenticated; separates reconnect messages from the first login
    pub ever_connected: Arc<AtomicBool>,
    /// `Arc` so `Session` can be `Clone` (as `session()` returns clones); clones share one sender handle, with `tx.lock()` auto-dereferencing through the `Arc`.
    pub tx: Arc<Mutex<Option<Sender<Outbound>>>>,
}

impl Session {
    pub fn username(&self) -> Option<String> {
        self.state.lock().unwrap().username.clone()
    }
    pub fn name(&self) -> String {
        self.name.lock().unwrap().clone()
    }
    pub fn set_name(&self, name: &str) {
        *self.name.lock().unwrap() = name.to_string();
    }
    /// "Online" = the WebSocket authenticated: connectivity with that server, not a contact's presence (see `online_contacts_snapshot`).
    pub fn status(&self) -> bool {
        self.ws_connected.load(Ordering::Relaxed)
    }
    /// Snapshot of online contacts (per server); returning a snapshot instead of borrowing lets the UI sort/render outside the lock.
    pub fn online_contacts_snapshot(&self) -> HashSet<String> {
        self.state.lock().unwrap().online_contacts.clone()
    }
    pub fn error(&self) -> Option<String> {
        self.state.lock().unwrap().error.clone()
    }
    pub fn unread(&self, contact: &str) -> i64 {
        *self.state.lock().unwrap().unread.get(contact).unwrap_or(&0)
    }
}

pub struct Core {
    pub store: Arc<Store>,
    pub sessions: Mutex<HashMap<String, Session>>,
    pub order: Mutex<Vec<String>>,
    /// Servers deleted at runtime (already removed from the DB; the in-memory slot is kept so old threads can exit safely)
    deleted_servers: Mutex<HashSet<String>>,
    pub current_server: Mutex<Option<String>>,
    pub current_contact: Mutex<Option<String>>,
    tx: Sender<Event>,
    priv_cache: Mutex<HashMap<String, Arc<rsa::RsaPrivateKey>>>,
    /// Shutdown flag: once set, all supervisor threads stop reconnecting and close live connections
    shutting_down: AtomicBool,
    /// Number of in-flight file downloads (drives the pre-exit confirmation dialog)
    active_downloads: Arc<AtomicU64>,
}

impl Core {
    /// Returns (core, event receiver). The receiver stays outside `Core` so `Core` itself can be shared across threads.
    pub fn new(store: Arc<Store>) -> Result<(Arc<Self>, Receiver<Event>)> {
        let (tx, rx) = channel();
        // Purge half-written contacts from `/add_contact` responses that had no key: without a key nothing can be encrypted, and `get_contacts` would keep them forever
        let purged = store.purge_keyless_contacts().unwrap_or(0);
        if purged > 0 {
            let _ = tx.send(Event::Toast(format!(
                "cleaned up {purged} contact records with no public key (add was incomplete)")));
        }
        let mut sessions = HashMap::new();
        let mut order = Vec::new();
        for s in store.get_servers()? {
            order.push(s.id.clone());
            sessions.insert(s.id.clone(), build_session(&store, &s)?);
        }
        let me = Arc::new(Self {
            store,
            sessions: Mutex::new(sessions),
            order: Mutex::new(order),
            deleted_servers: Mutex::new(HashSet::new()),
            current_server: Mutex::new(None),
            current_contact: Mutex::new(None),
            tx,
            priv_cache: Mutex::new(HashMap::new()),
            shutting_down: AtomicBool::new(false),
            active_downloads: Arc::new(AtomicU64::new(0)),
        });
        // Leftover `sent` from a previous run lost its ack and is unknowable: downgrade to unknown with neutral wording, so it is not misread as "not delivered" and resent
        me.mark_stale_sends();
        Ok((me, rx))
    }

    /// At startup, downgrade leftover `local_status=sent` to `unknown` before `Ui` is built, so later `reload_chat` calls see the settled state; failures only log to stderr.
    fn mark_stale_sends(&self) {
        match self.store.downgrade_pending_sends(store::LOCAL_STATUS_UNKNOWN) {
            Ok(0) => {}
            Ok(n) => crate::tui_log!("marked {n} messages from the previous run as unacknowledged"),
            Err(e) => crate::tui_log!("failed to downgrade pending-ack messages: {e:#}"),
        }
    }

    pub fn emit(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    /// Number of in-flight file downloads (drives the pre-exit confirmation dialog, so users do not assume everything finished)
    pub fn active_downloads(&self) -> u64 {
        self.active_downloads.load(Ordering::SeqCst)
    }

    /// After login, resume files whose chunks are still in `received_files/.part/` (killed process / dropped network) instead of asking the peer to resend.
    pub fn resume_pending_downloads(self: &Arc<Self>, sid: &str) {
        let part_dir = partial_dir();
        let Ok(rd) = std::fs::read_dir(&part_dir) else { return };
        let mut partials: HashMap<String, u64> = HashMap::new();
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            let Some(file_id) = name.strip_suffix(".enc") else { continue };
            let len = ent.metadata().map(|m| m.len()).unwrap_or(0);
            if len > 0 {
                partials.insert(file_id.to_string(), len);
            }
        }
        if partials.is_empty() {
            return;
        }

        let pending = match self.store.list_pending_file_downloads(sid) {
            Ok(v) => v,
            Err(e) => {
                crate::tui_log!("failed to scan for resumable files: {e:#}");
                return;
            }
        };
        for row in pending {
            let Ok(obj) = serde_json::from_str::<Value>(&row.content) else { continue };
            let file_id = obj.get("file_id").and_then(|v| v.as_str()).unwrap_or("");
            let Some(have) = partials.get(file_id) else { continue };
            let size = obj.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            if have >= &size {
                continue; // fully downloaded; hand off to the normal decrypt path
            }
            let sender = row.sender.clone();
            crate::tui_log!("resuming unfinished file receive file_id={file_id} ({have}/{size} bytes)");
            self.emit(Event::Toast(format!(
                "continue receiving the unfinished file ({have}/{size} bytes)")));
            self.spawn_download_file(sid, &sender, obj);
        }
    }

    pub fn is_deleted(&self, sid: &str) -> bool {
        self.deleted_servers.lock().unwrap().contains(sid)
    }

    /// Order of servers not deleted at runtime (deleted ones are no longer shown or connected)
    pub fn live_order(&self) -> Vec<String> {
        let del = self.deleted_servers.lock().unwrap();
        self.order.lock().unwrap().iter()
            .filter(|s| !del.contains(*s)).cloned().collect()
    }

    /// Return a **clone** of the session (cheap: all `Arc`s and small values); `sessions` is a `Mutex<HashMap>`, so no borrow can be returned.
    pub fn session(&self, sid: &str) -> Option<Session> {
        if self.is_deleted(sid) {
            return None;
        }
        self.sessions.lock().unwrap().get(sid).cloned()
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Called on exit: stop all automatic reconnection and tell every WS thread to close.
    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::SeqCst);
        for s in self.sessions.lock().unwrap().values() {
            if let Some(tx) = s.tx.lock().unwrap().as_ref() {
                let _ = tx.send(Outbound::Stop);
            }
        }
    }

    pub fn cur_server(&self) -> Option<String> {
        self.current_server.lock().unwrap().clone()
    }
    pub fn cur_contact(&self) -> Option<String> {
        self.current_contact.lock().unwrap().clone()
    }
    pub fn username_of(&self, sid: &str) -> Option<String> {
        self.session(sid).and_then(|s| s.username())
    }

    /// Cache of parsed private keys (RSA parsing is expensive, so parse once)
    pub fn priv_key(&self, sid: &str) -> Option<Arc<rsa::RsaPrivateKey>> {
        if let Some(k) = self.priv_cache.lock().unwrap().get(sid) {
            return Some(k.clone());
        }
        let pem = self.priv_pem(sid)?;
        let key = Arc::new(crypto::parse_private(&pem).ok()?);
        self.priv_cache.lock().unwrap().insert(sid.to_string(), key.clone());
        Some(key)
    }

    fn priv_pem(&self, sid: &str) -> Option<String> {
        let uname = self.username_of(sid)?;
        self.store.get_identity(sid, &uname).ok()?.map(|i| i.private_key)
    }

    /// Add a server: write to the DB → build the runtime session → **connect immediately** (no restart).
    /// Updates `sessions`/`order` at runtime and returns the new server id (for selection/toasts).
    pub fn add_server(
        self: &Arc<Self>, name: &str, host: &str, port: i64,
    ) -> Result<String> {
        let name = name.trim();
        let host = host.trim();
        if host.is_empty() {
            anyhow::bail!("server address must not be empty");
        }
        if !(store::PORT_MIN..=store::PORT_MAX).contains(&port) {
            anyhow::bail!("port must be an integer in {}..{}", store::PORT_MIN, store::PORT_MAX);
        }
        let name = if name.is_empty() { format!("{host}:{port}") } else { name.to_string() };

        let sid = crate::crypto::generate_msg_id()[..8].to_string();
        self.store.insert_server(&sid, &name, host, port)?;

        // Build and register the session; roll the DB row back on any failure, so no half-created "recorded but never connectable" server is left behind.
        let server = store::Server {
            id: sid.clone(), name, host: host.to_string(), api_port: port,
        };
        let built = build_session(&self.store, &server);
        let sess = match built {
            Ok(s) => s,
            Err(e) => {
                let _ = self.store.delete_server(&sid);
                return Err(e);
            }
        };
        self.sessions.lock().unwrap().insert(sid.clone(), sess);
        self.order.lock().unwrap().push(sid.clone());

        self.emit(Event::ServersChanged);
        self.connect_one(sid.clone());
        Ok(sid)
    }

    pub fn connect_all(self: &Arc<Self>) {
        for sid in self.live_order() {
            self.connect_one(sid);
        }
    }

    /// Connect one server (no-op if already connected/connecting); starts the supervisor: login + WS setup, then backoff reconnect until deleted or shutdown.
    pub fn connect_one(self: &Arc<Self>, sid: String) {
        let Some(sess) = self.session(&sid) else { return };
        if sess.connecting.swap(true, Ordering::SeqCst) {
            self.emit(Event::Toast(format!("[{}] connected or connecting", sess.name())));
            return;
        }
        let me = self.clone();
        let guard = self.clone();
        let sid_for_guard = sid.clone();
        let sid_for_thread = sid.clone();
        let spawned = thread::Builder::new()
            .name(format!("connect-{sid}"))
            .spawn(move || {
                // A panic in the supervisor must not leave `connecting` true, or the server could never be reconnected by hand
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    me.supervise_connection(&sid_for_thread);
                }));
                if outcome.is_err() {
                    if let Some(s) = guard.session(&sid_for_guard) {
                        s.connecting.store(false, Ordering::SeqCst);
                        s.ws_connected.store(false, Ordering::SeqCst);
                        s.state.lock().unwrap().error =
                            Some("connection thread terminated unexpectedly; press Enter to reconnect".into());
                    }
                    guard.emit(Event::ServersChanged);
                }
            });
        if let Err(e) = spawned {
            // Reset the flag when the thread cannot even be started, or the server becomes permanently unreconnectable
            if let Some(s) = self.session(&sid) {
                s.connecting.store(false, Ordering::SeqCst);
                s.state.lock().unwrap().error = Some(format!("cannot start connection thread: {e}"));
            }
            self.emit(Event::ServersChanged);
        }
    }

    /// Supervisor loop (run on its own thread by `connect_one`): login → WS → backoff reconnect until the server is deleted or we shut down.
    fn supervise_connection(self: &Arc<Self>, sid: &str) {
        let mut backoff_secs: u64 = 1;
        loop {
            if self.is_deleted(sid) || self.is_shutting_down() { break; }

            // Re-run challenge login (an existing username is not re-registered), then login_flow → start_ws brings up the WS thread.
            let r = self.login_flow(sid);
            let ok = r.is_ok();
            if let Err(e) = r {
                let msg = format!("{e:#}");
                if let Some(s) = self.session(sid) {
                    s.ws_connected.store(false, Ordering::SeqCst);
                    s.state.lock().unwrap().error = Some(msg.clone());
                    self.emit(Event::LoginStatus {
                        text: format!("[{}] connection failed: {msg}", s.name()),
                    });
                }
            }
            self.emit(Event::LoginFinished { ok });
            self.emit(Event::ServersChanged);

            // Login never established a WS: that is a connect failure, not a disconnect, so do not overwrite the real error recorded above.
            if !ok {
                if self.is_deleted(sid) || self.is_shutting_down() { break; }
                if let Some(s) = self.session(sid) {
                    self.emit(Event::Toast(format!(
                        "[{}] connection failed, retrying in {} seconds", s.name(), backoff_secs)));
                }
                thread::sleep(Duration::from_secs(backoff_secs));
                backoff_secs = (backoff_secs * 2).min(30);
                continue;
            }

            let mut ever_online = false;
            loop {
                if self.is_deleted(sid) || self.is_shutting_down() { break; }
                let Some(s) = self.session(sid) else { break };
                if !s.ws_alive.load(Ordering::SeqCst) { break; }
                if s.status() { ever_online = true; }
                thread::sleep(Duration::from_millis(300));
            }
            if self.is_deleted(sid) || self.is_shutting_down() { break; }

            if ever_online { backoff_secs = 1; }
            if let Some(s) = self.session(sid) {
                s.ws_connected.store(false, Ordering::SeqCst);
                s.state.lock().unwrap().error = Some("connection lost, reconnecting automatically...".into());
                self.emit(Event::Toast(format!(
                    "[{}] connection lost, reconnecting automatically in {} seconds", s.name(), backoff_secs)));
            }
            self.emit(Event::ServersChanged);
            thread::sleep(Duration::from_secs(backoff_secs));
            backoff_secs = (backoff_secs * 2).min(30);
        }
        if let Some(s) = self.session(sid) {
            s.connecting.store(false, Ordering::SeqCst);
        }
        self.emit(Event::ServersChanged);
    }

    fn login_flow(self: &Arc<Self>, sid: &str) -> Result<()> {
        if self.is_deleted(sid) {
            return Ok(());
        }
        let (name, mut username) = {
            let s = self.session(sid).context("no such server")?;
            (s.name(), s.username())
        };

        if username.is_none() {
            self.emit(Event::LoginStatus {
                text: format!("[{name}] generating keypair (4096-bit)..."),
            });
            let (priv_pem, pub_pem) = crypto::generate_keypair()?;
            let uname = crypto::public_key_id(&pub_pem, 10)?;
            let reg = self.rest(sid, "POST", "/register",
                Some(json!({"user_id": uname, "public_key": pub_pem})))?;
            if reg.get("status").and_then(|v| v.as_str()) != Some("ok") {
                anyhow::bail!("register failed: {}", reg.pointer("/error/message")
                    .and_then(|v| v.as_str()).unwrap_or("unknown error"));
            }
            self.store.upsert_identity(&store::Identity {
                server_id: sid.into(), username: uname.clone(),
                private_key: priv_pem, public_key: pub_pem,
            })?;
            self.store.set_state(&format!("current_user_{sid}"), &uname)?;
            username = Some(uname);
        }
        let username = username.unwrap();
        if let Some(s) = self.session(sid) {
            s.state.lock().unwrap().username = Some(username.clone());
        }

        let ch = self.rest(sid, "POST", "/login/challenge", Some(json!({"user_id": username})))?;
        let challenge = ch.pointer("/payload/challenge").and_then(|v| v.as_str())
            .context("failed to fetch challenge")?.to_string();
        let key = self.priv_key(sid).context("missing private key")?;
        let signature = crypto::sign_message_with_key(&key, &crypto::md5_hex(&challenge))?;
        let login = self.rest(sid, "POST", "/login",
            Some(json!({"user_id": username, "signature": signature})))?;
        if login.get("status").and_then(|v| v.as_str()) != Some("ok") {
            anyhow::bail!("login failed: {}", login.pointer("/error/message")
                .and_then(|v| v.as_str()).unwrap_or("unknown error"));
        }
        if let Some(tok) = login.pointer("/payload/token").and_then(|v| v.as_str()) {
            self.store.set_token(sid, tok)?;
        }
        if self.is_deleted(sid) {
            return Ok(());
        }
        // `payload.contacts` from `/login` is deliberately not stored: a contact is written only after an explicit `/add_contact` verified the peer's key
        let ever = self.session(sid).map(|s| s.ever_connected.load(Ordering::SeqCst)).unwrap_or(false);
        self.emit(Event::LoginStatus {
            text: if ever {
                format!("[{name}] reconnected  ID: {username}")
            } else {
                format!("[{name}] login OK  ID: {username}")
            },
        });
        if self.cur_server().is_none() {
            *self.current_server.lock().unwrap() = Some(sid.to_string());
        }
        self.start_ws(sid.to_string(), username.clone())?;
        // fetch offline messages on a thread so login is not blocked
        {
            let me = self.clone();
            let sid2 = sid.to_string();
            let uname = username.clone();
            thread::spawn(move || {
                if let Err(e) = me.fetch_offline(&sid2, &uname) {
                    me.emit(Event::Toast(format!("failed to fetch offline messages: {e:#}")));
                }
                if let Err(e) = me.fetch_contacts_online(&sid2) {
                    crate::tui_log!("presence query failed sid={sid2}: {e:#}");
                }
                // resume unfinished file downloads after the offline catch-up (the file messages are in the DB by now)
                me.resume_pending_downloads(&sid2);
            });
        }
        Ok(())
    }

    fn host_port(&self, sid: &str) -> Result<(String, u16)> {
        let s = self.session(sid).context("no such server")?;
        Ok((s.host.clone(), s.port))
    }

    /// Open an HTTPS connection with SPKI-fingerprint TOFU verification.
    fn https_conn(&self, sid: &str, timeout: Duration)
        -> Result<(net::http::HttpsConn, Arc<Mutex<Option<String>>>)>
    {
        let (host, port) = self.host_port(sid)?;
        let saved = self.store.get_cert_pin(sid)?;
        let seen = Arc::new(Mutex::new(None::<String>));
        let seen2 = seen.clone();
        let check: net::tls::PinCheck = Arc::new(move |pin: &str| {
            *seen2.lock().unwrap() = Some(pin.to_string());
            match &saved {
                None => Ok(()),
                Some(s) if s == pin => Ok(()),
                Some(s) => Err(format!("certificate fingerprint changed! expected {s}, actual {pin} (possible man-in-the-middle attack)")),
            }
        });
        let conn = net::http::HttpsConn::connect(
            &host, port, net::tls::client_config(Some(check)), timeout)?;
        Ok((conn, seen))
    }

    fn record_pin_if_new(&self, sid: &str, seen: &Arc<Mutex<Option<String>>>) -> Result<()> {
        if let Some(pin) = seen.lock().unwrap().clone() {
            if self.store.get_cert_pin(sid)?.is_none() {
                self.store.set_cert_pin(sid, &pin)?;
                self.emit(Event::Toast(format!(
                    "recorded the server certificate fingerprint (first connection)\n{}", fmt_pin(&pin))));
            }
        }
        Ok(())
    }

    fn rest_upload_file(&self, sid: &str, path: &str, file: &Path) -> Result<(u16, Vec<u8>)> {
        let (host, port) = self.host_port(sid)?;
        let (mut conn, seen) = self.https_conn(sid, FILE_TIMEOUT)?;
        let len = std::fs::metadata(file).context("failed to stat the upload file")?.len();
        let r = conn.request_upload_file(
            "POST", path, &host, port, "application/octet-stream", file, len)?;
        self.record_pin_if_new(sid, &seen)?;
        Ok(r)
    }

    fn rest_download_file(
        &self, sid: &str, path: &str, dest: &Path, resume_from: u64,
    ) -> Result<(u16, Vec<u8>)> {
        let (host, port) = self.host_port(sid)?;
        let (mut conn, seen) = self.https_conn(sid, FILE_TIMEOUT)?;
        let r = conn.request_download_to_file("GET", path, &host, port, dest, resume_from)?;
        self.record_pin_if_new(sid, &seen)?;
        Ok(r)
    }

    /// Generic REST call (JSON, with SPKI pinning via TOFU)
    pub(crate) fn rest(&self, sid: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let (host, port) = self.host_port(sid)?;
        let (mut conn, seen) = self.https_conn(sid, Duration::from_secs(15))?;
        let (status, v) = conn.request_json(method, path, &host, port, body.as_ref())?;
        self.record_pin_if_new(sid, &seen)?;
        if status >= 400 {
            anyhow::bail!("HTTP {status}: {}", serde_json::to_string(&v).unwrap_or_default());
        }
        Ok(v)
    }

    /// Like `rest` but returns the body unparsed: offline messages need this, since `serde_json` re-formats f64 and only the raw timestamp string verifies.
    fn rest_raw(&self, sid: &str, method: &str, path: &str, body: Option<Value>)
        -> Result<(u16, Vec<u8>)>
    {
        let (host, port) = self.host_port(sid)?;
        let (mut conn, seen) = self.https_conn(sid, Duration::from_secs(15))?;
        let bytes = match body.as_ref() {
            Some(v) => {
                let payload = serde_json::to_vec(v).context("failed to serialize request body")?;
                conn.request_with_type(method, path, &host, port, None, Some(&payload))?
            }
            None => conn.request_with_type(method, path, &host, port, None, None)?,
        };
        self.record_pin_if_new(sid, &seen)?;
        Ok(bytes)
    }

    fn start_ws(self: &Arc<Self>, sid: String, username: String) -> Result<()> {
        if self.is_deleted(&sid) || self.is_shutting_down() {
            return Ok(());
        }
        let (host, port, conn_flag, alive, epoch_arc) = {
            // Clone all `Arc`s up front: repeated `session().unwrap()` would panic the thread if a concurrent deletion removes the session
            let s = self.session(&sid).context("no such server")?;
            (s.host.clone(), s.port, s.ws_connected.clone(),
             s.ws_alive.clone(), s.ws_epoch.clone())
        };
        let token = self.store.get_token(&sid)?.unwrap_or_default();
        let (tx, rx) = channel::<Outbound>();
        let me = self.clone();
        let sid2 = sid.clone();
        let flag2 = conn_flag.clone();
        let epoch = epoch_arc.fetch_add(1, Ordering::SeqCst) + 1;
        // Set alive synchronously first, so the supervisor does not mistake a just-created WS thread for a dead one and reconnect twice
        alive.store(true, Ordering::SeqCst);
        flag2.store(false, Ordering::SeqCst);
        // Stop any old WS thread (its epoch is stale, so it will not clear this alive flag)
        {
            let s = self.session(&sid).context("no such server")?;
            if let Some(old) = s.tx.lock().unwrap().take() {
                let _ = old.send(Outbound::Stop);
            }
            s.state.lock().unwrap().error = None;
        }
        thread::spawn(move || {
            let res = me.ws_loop(&sid2, &host, port, &username, &token, rx, &flag2);
            flag2.store(false, Ordering::SeqCst);
            if epoch_arc.load(Ordering::SeqCst) == epoch {
                alive.store(false, Ordering::SeqCst);
            }
            if let Some(s) = me.session(&sid2) {
                if let Err(e) = &res {
                    s.state.lock().unwrap().error = Some(format!("{e:#}"));
                }
            }
            // Disconnects are announced and retried by connect_one's supervisor, so no duplicate toast here
            me.emit(Event::ServersChanged);
        });
        self.session(&sid).context("no such server")?
            .tx.lock().unwrap().replace(tx);
        Ok(())
    }

    fn ws_loop(
        self: &Arc<Self>, sid: &str, host: &str, port: u16, username: &str, token: &str,
        rx: Receiver<Outbound>, connected: &Arc<AtomicBool>,
    ) -> Result<()> {
        let mut ws = net::ws::WsClient::connect(host, port, "/ws",
            net::tls::client_config(None), Duration::from_secs(10))?;
        ws.send_text(&json!({"type":"connect",
            "payload":{"user_id":username,"token":token},"request_id":"c1"}).to_string())?;

        // Auth: go online only on success; bail immediately on an explicit server error instead of waiting out the 10s
        let mut authed = false;
        let start = Instant::now();
        while !authed {
            if start.elapsed() > Duration::from_secs(10) {
                anyhow::bail!("WS authentication timed out");
            }
            match ws.read_frame()? {
                Some(net::ws::WsFrame::Text(t)) => {
                    let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                    let typ = v.get("type").and_then(|x| x.as_str()).unwrap_or("");
                    let status = v.get("status").and_then(|x| x.as_str()).unwrap_or("");
                    if typ == "connect" && status == "ok" {
                        authed = true;
                    } else if typ == "error" || status == "error" {
                        let msg = v.pointer("/error/message").and_then(|m| m.as_str())
                            .unwrap_or("WS authentication failed (invalid token?)");
                        anyhow::bail!("{msg}");
                    }
                }
                Some(net::ws::WsFrame::Close) => anyhow::bail!("WS closed before authentication completed"),
                _ => {}
            }
            match rx.try_recv() {
                Ok(Outbound::Text(t)) => { let _ = ws.send_text(&t); }
                Ok(Outbound::Stop) => { ws.send_close().ok(); return Ok(()); }
                Err(_) => {}
            }
        }
        connected.store(true, Ordering::SeqCst);
        if let Some(s) = self.session(sid) {
            s.ever_connected.store(true, Ordering::SeqCst);
        }
        self.emit(Event::ServersChanged);

        let mut last_beat = Instant::now();
        loop {
            loop {
                match rx.try_recv() {
                    Ok(Outbound::Text(t)) => {
                        ws.send_text(&t)?;
                    }
                    Ok(Outbound::Stop) => { ws.send_close().ok(); return Ok(()); }
                    Err(_) => break,
                }
            }
            if last_beat.elapsed() > Duration::from_secs(30) {
                // A failed heartbeat means the link is gone; return so the supervisor reconnects
                ws.send_text(&json!({"type":"heartbeat","payload":{}}).to_string())?;
                last_beat = Instant::now();
            }
            match ws.read_frame() {
                Ok(Some(net::ws::WsFrame::Text(t))) => self.handle_ws_text(sid, &t),
                Ok(Some(net::ws::WsFrame::Ping(_))) => { /* tungstenite answers Pong automatically */ }
                Ok(Some(net::ws::WsFrame::Close)) => return Ok(()),
                Ok(None) => {} // read timed out; keep polling the outbound queue / heartbeat
                Ok(Some(_)) => {}
                Err(e) => return Err(e),
            }
        }
    }

    fn handle_ws_text(self: &Arc<Self>, sid: &str, text: &str) {
        let v: Value = match serde_json::from_str(text) { Ok(v) => v, Err(_) => return };
        match v.get("type").and_then(|x| x.as_str()) {
            Some("new_message") => {
                if let Some(p) = v.get("payload") {
                    // pass the raw text: verification needs the original JSON timestamp token (see store_incoming)
                    if let Err(e) = self.store_incoming(sid, p, text) {
                        self.emit(Event::Toast(format!("message handling failed: {e:#}")));
                    }
                }
            }
            Some("presence") => {
                // contact online/offline push (broadcast by the server on connect/disconnect)
                if let Some(p) = v.get("payload") {
                    self.handle_presence(sid, p);
                }
            }
            // Group pushes only mark dirty here: this runs on the WS receive thread, so network I/O or MLS decryption would
            // stall heartbeats and 1v1 delivery. The `group::runtime::start_worker` thread does the actual sync.
            Some("group_new_message") | Some("group_notify") => {
                if let Some(gid) = v.pointer("/payload/group_id").and_then(|x| x.as_str()) {
                    let reason = v
                        .pointer("/payload/reason")
                        .and_then(|x| x.as_str())
                        .unwrap_or("");
                    if let Some(sess) = self.session(sid) {
                        sess.group_runtime.mark(sid, gid);
                        // join_request (owners/admins) and transfer (the designee, usually a plain member) mean "someone awaits you", so both light up F7
                        if reason == "join_request" || reason == "transfer" {
                            sess.group_runtime.mark_approval(sid, gid);
                        }
                    }
                    crate::group::runtime::start_worker(self, sid);
                }
            }
            // Someone added me one-way: light up F7; the real request list still comes from POST /contacts/pending_incoming
            Some("contact_notify") => {
                let from = v
                    .pointer("/payload/from")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                self.emit(Event::FriendRequest { sid: sid.to_string(), from });
            }
            Some("presence_snapshot") => {
                // Full snapshot every 30s: replace the online set wholesale, correcting lost incremental pushes
                if let Some(p) = v.get("payload") {
                    self.handle_presence_snapshot(sid, p);
                }
            }
            Some("send_message") => {
                // The ack carries msg_id / to / delivered / error; correlating by msg_id is mandatory, or a rejected message would still render as sent
                let msg_id = v.pointer("/payload/msg_id").and_then(|x| x.as_str()).unwrap_or("");
                let err_msg = v.pointer("/payload/error/message").and_then(|m| m.as_str());
                let rejected = v.pointer("/payload/error").is_some();
                let delivered = v.pointer("/payload/delivered").and_then(|d| d.as_bool()).unwrap_or(false);

                let status = if rejected {
                    // explicit server rejection (NOT_MUTUAL / unencrypted / bad signature / queue full…)
                    store::LOCAL_STATUS_FAILED
                } else if delivered {
                    // peer online; the server pushed it straight to their connection
                    store::LOCAL_STATUS_DELIVERED
                } else {
                    // No error and delivered=false means the server queued it for an offline peer — still a success; showing "not delivered" was a false alarm
                    store::LOCAL_STATUS_QUEUED
                };
                if !msg_id.is_empty() {
                    self.apply_send_ack(sid, msg_id, status, err_msg);
                }
                if rejected {
                    self.emit(Event::Toast(format!("send failed: {}", err_msg.unwrap_or("rejected by the server"))));
                }
            }
            _ => {}
        }
    }

    /// Handle one received message (WS `new_message` or an offline payload); `Ok(true)` means a new row was stored.
    /// Only locally added contacts with a verifying signature are admitted. `raw_text` is mandatory for verification: parsing f64 changes low digits (~12%), so a digest rebuilt from it fails at random and the message is dropped.
    pub fn store_incoming(self: &Arc<Self>, sid: &str, p: &Value, raw_text: &str) -> Result<bool> {
        let sender = p.get("from").and_then(|v| v.as_str()).unwrap_or("");
        let username = self.username_of(sid).unwrap_or_default();
        if sender.is_empty() || sender == username { return Ok(false); }

        // Only contacts I actively added (public_key non-empty) are accepted; a one-way add writes nothing locally, so anything sent before I add them is dropped, leaving no path around signature checks
        let pub_pem = match self.store.get_contact_public_key(sid, sender)? {
            Some(k) if !k.trim().is_empty() => k,
            _ => {
                self.emit(Event::Toast(
                    "message from a contact that has not been added, ignored (add them with F2 first)".into()));
                return Ok(false);
            }
        };
        let sig = p.get("signature").and_then(|v| v.as_str()).unwrap_or("");
        if sig.is_empty() {
            self.emit(Event::Toast(format!("message from {sender} has no signature, dropped")));
            return Ok(false);
        }
        let fields = crypto::build_message_fields_with_ts(
            s(p, "msg_id"), &username, sender,
            // the timestamp must come from the raw JSON token, never as_f64() (it changes low digits)
            &store::extract_timestamp_token(raw_text)
                .unwrap_or_else(|| s(p, "timestamp").to_string()),
            s(p, "msg_type"), s(p, "ciphertext"), s(p, "iv"), s(p, "tag"),
            s(p, "wrapped_key"), s(p, "file_id"), s(p, "filename"),
            p.get("size").and_then(|v| v.as_i64()).unwrap_or(0), s(p, "sha256"));
        let mut verified = crypto::verify_message_signature(&pub_pem, &fields, sig).unwrap_or(false);
        if !verified {
            // The local key may be stale (peer rotated it, or add_contact raced). The server could only forward this message
            // with a verifying key, so refetch and accept the new key only if it validates this signature.
            if let Ok(fresh) = self.fetch_remote_public_key(sid, sender) {
                if fresh != pub_pem
                    && crypto::verify_message_signature(&fresh, &fields, sig).unwrap_or(false)
                {
                    self.store.set_contact_public_key(sid, sender, &fresh)?;
                    verified = true;
                    self.emit(Event::Toast(format!(
                        "updated the public key of contact {sender} (the old key could not verify this message)")));
                }
            }
        }
        if !verified {
            self.emit(Event::Toast(format!(
                "signature verification failed, dropped the message from {sender} (the local public key may be stale; re-add the contact)")));
            return Ok(false);
        }

        let msg_type = s(p, "msg_type");
        let mut plaintext = String::new();
        if msg_type != "file" {
            // A normal client never lacks keys; drop the message if the key is missing or decryption fails rather than storing placeholder text
            let key = match self.priv_key(sid) {
                Some(k) => k,
                None => {
                    self.emit(Event::Toast(format!("missing local private key, dropped the message from {sender}")));
                    return Ok(false);
                }
            };
            match crypto::decrypt_text_with_key(
                s(p, "ciphertext"), s(p, "iv"), s(p, "tag"), s(p, "wrapped_key"), &key)
            {
                Ok(pt) => plaintext = pt,
                Err(e) => {
                    self.emit(Event::Toast(format!("decryption failed, dropped the message from {sender}: {e}")));
                    return Ok(false);
                }
            }
        }
        let store_obj = json!({
            "from": s(p, "from"), "ciphertext": s(p, "ciphertext"), "iv": s(p, "iv"),
            "tag": s(p, "tag"), "msg_id": s(p, "msg_id"), "timestamp": p.get("timestamp"),
            "msg_type": s(p, "msg_type"), "file_id": s(p, "file_id"),
            "filename": s(p, "filename"), "size": p.get("size").and_then(|v| v.as_i64()).unwrap_or(0),
            "sha256": s(p, "sha256"), "wrapped_key": s(p, "wrapped_key"),
            "signature": s(p, "signature")
        });
        let ts = p.get("timestamp").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let chat_key = store::make_chat_key(&username, sender);
        let inserted = self.store.insert_message(
            sid, &chat_key, p.get("msg_id").and_then(|v| v.as_str()),
            sender, &store_obj.to_string(), &store::fmt_db_time(ts), &plaintext)?;
        if !inserted { return Ok(false); }

        if msg_type == "file" {
            self.spawn_download_file(sid, sender, p.clone());
        }

        if self.cur_server().as_deref() == Some(sid) && self.cur_contact().as_deref() == Some(sender) {
            self.emit(Event::ChatUpdated { server_id: sid.into(), contact: sender.into() });
        } else {
            self.store.bump_unread(sid, sender, 1)?;
            let mut unread = 0;
            if let Some(s) = self.session(sid) {
                let mut st = s.state.lock().unwrap();
                let e = st.unread.entry(sender.to_string()).or_insert(0);
                *e += 1;
                unread = *e;
            }
            // incremental unread update, so each message does not trigger a full rebuild_tree
            self.emit(Event::UnreadChanged {
                server_id: sid.into(), contact: sender.into(), unread, delta: 1,
            });
        }
        Ok(true)
    }

    /// Fetch offline messages (signed request).
    pub fn fetch_offline(self: &Arc<Self>, sid: &str, username: &str) -> Result<()> {
        if self.is_deleted(sid) {
            return Ok(());
        }
        let key = self.priv_key(sid).context("missing private key")?;
        let mut body = json!({"user_id": username});
        let signed = crypto::signed_request_body_with_key(&key, &[username.to_string()])?;
        if let (Some(o), Some(sg)) = (body.as_object_mut(), signed.as_object()) {
            for (k, v) in sg { o.insert(k.clone(), v.clone()); }
        }
        // use the raw response body: each message's number token must reach verification verbatim
        let (status, raw) = self.rest_raw(sid, "POST", "/get_offline_msg", Some(body))?;
        if status >= 400 {
            anyhow::bail!("failed to fetch offline messages: HTTP {status}: {}",
                          String::from_utf8_lossy(&raw).trim());
        }
        let res: Value = serde_json::from_slice(&raw).context("failed to parse the offline messages response")?;
        if res.get("status").and_then(|v| v.as_str()) != Some("ok") {
            anyhow::bail!("failed to fetch offline messages: {}", res.pointer("/error/message")
                .and_then(|v| v.as_str()).unwrap_or("unknown error"));
        }
        // Slice each message byte-wise from the **raw response text**: `Value::to_string()` re-formats f64 timestamps (~12%), breaking the signature digest
        let raw_msgs = store::extract_json_array_objects(
            &String::from_utf8_lossy(&raw), "messages");
        let parsed_msgs: Vec<Value> = res.pointer("/payload/messages")
            .and_then(|v| v.as_array()).cloned().unwrap_or_default();
        if raw_msgs.len() != parsed_msgs.len() {
            anyhow::bail!("malformed offline messages response (raw {} entries / parsed {} entries)",
                          raw_msgs.len(), parsed_msgs.len());
        }
        let mut n = 0usize;
        let mut failed = 0usize;
        let mut first_err: Option<String> = None;
        for (m, m_text) in parsed_msgs.iter().zip(raw_msgs.iter()) {
            match self.store_incoming(sid, m, m_text) {
                Ok(true) => n += 1,
                Ok(false) => {}
                Err(e) => {
                    // The server already dequeued this message, so a storage failure is permanent loss: count it and report instead of swallowing it
                    failed += 1;
                    let msg = format!("{e:#}");
                    if first_err.is_none() { first_err = Some(msg); }
                }
            }
        }
        if n > 0 {
            self.emit(Event::Toast(format!("fetched {n} offline messages")));
        }
        if failed > 0 {
            let detail = first_err.unwrap_or_else(|| "unknown reason".into());
            self.emit(Event::Toast(format!(
                "{failed} offline messages failed to process (deleted from the server): {detail}")));
            crate::tui_log!("failed to process {failed} offline messages: {detail}");
        }
        Ok(())
    }

    /// Fetch presence (signed REST) for **locally added** contacts only (the server ignores unknown IDs) and replace the cached set; failures only log, never block login.
    pub fn fetch_contacts_online(self: &Arc<Self>, sid: &str) -> Result<()> {
        if self.is_deleted(sid) {
            return Ok(());
        }
        let username = self.username_of(sid).context("not logged in")?;
        let key = self.priv_key(sid).context("missing private key")?;
        let contacts: Vec<String> = self.store.get_contacts(sid)?
            .into_iter()
            .filter(|c| c.deleted == 0)
            .map(|c| c.username)
            .collect();
        if contacts.is_empty() {
            if let Some(s) = self.session(sid) {
                s.state.lock().unwrap().online_contacts.clear();
            }
            self.emit(Event::PresenceRefreshed { server_id: sid.to_string() });
            return Ok(());
        }

        // the signature covers [user_id] + contacts + timestamp + nonce (as on the server)
        let mut fields = vec![username.clone()];
        fields.extend(contacts.iter().cloned());
        let (ts, nonce, sig) = crypto::build_signed_params_with_key(&key, &fields)?;
        let body = json!({
            "user_id": username,
            "contacts": contacts,
            "timestamp": ts,
            "nonce": nonce,
            "signature": sig,
        });
        // rest_raw keeps the raw body (no f64 re-serialization) and returns Err for the caller to log, with no toast (no promise of compatibility with old servers)
        let (status, raw) = self.rest_raw(sid, "POST", "/contacts/online", Some(body))?;
        if status >= 400 {
            anyhow::bail!("presence query failed: HTTP {status}");
        }
        let res: Value = serde_json::from_slice(&raw).context("failed to parse the presence response")?;
        if res.get("status").and_then(|v| v.as_str()) != Some("ok") {
            anyhow::bail!("presence query failed: {}", res.pointer("/error/message")
                .and_then(|v| v.as_str()).unwrap_or("unknown error"));
        }
        let online: HashSet<String> = res.pointer("/payload/online")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        crate::tui_log!("presence refresh sid={sid}: {}/{} online",
                        online.len(), contacts.len());
        if let Some(s) = self.session(sid) {
            s.state.lock().unwrap().online_contacts = online;
        }
        self.emit(Event::PresenceRefreshed { server_id: sid.to_string() });
        Ok(())
    }

    fn handle_presence(self: &Arc<Self>, sid: &str, p: &Value) {
        let contact = p.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
        let online = p.get("online").and_then(|v| v.as_bool()).unwrap_or(false);
        if contact.is_empty() { return; }

        // accept only locally added contacts, so no presence appears for someone absent from the tree
        let known = self.store.get_contacts(sid)
            .map(|cs| cs.into_iter().any(|c| c.username == contact && c.deleted == 0))
            .unwrap_or(false);
        if !known { return; }

        let changed = match self.session(sid) {
            Some(s) => {
                let mut st = s.state.lock().unwrap();
                if online { st.online_contacts.insert(contact.to_string()) }
                else { st.online_contacts.remove(contact) }
            }
            None => return,
        };
        // no UI refresh when nothing changed (presence pushes may repeat)
        if changed {
            crate::tui_log!("presence sid={sid} {contact} online={online}");
            self.emit(Event::PresenceChanged {
                server_id: sid.to_string(), contact: contact.to_string(), online,
            });
        }
    }

    /// Full `presence_snapshot`: unlike incremental presence it **replaces** the online set, correcting drift such as a stale "online" from a lost broadcast.
    fn handle_presence_snapshot(self: &Arc<Self>, sid: &str, p: &Value) {
        let Some(obj) = p.get("contacts").and_then(|v| v.as_object()) else { return };
        let Some(sess) = self.session(sid) else { return };

        let known: HashSet<String> = self.store.get_contacts(sid)
            .map(|cs| cs.into_iter()
                .filter(|c| c.deleted == 0)
                .map(|c| c.username)
                .collect())
            .unwrap_or_default();

        let (changed, n) = {
            let mut st = sess.state.lock().unwrap();
            let fresh = merge_presence_snapshot(&st.online_contacts, obj, &known);
            let changed = st.online_contacts != fresh;
            if changed { st.online_contacts = fresh; }
            (changed, st.online_contacts.len())
        };
        if changed {
            crate::tui_log!("presence_snapshot sid={sid}: {n} online");
            self.emit(Event::PresenceRefreshed { server_id: sid.to_string() });
        }
    }

    pub fn send_text(self: &Arc<Self>, content: &str) -> Result<()> {
        let sid = self.cur_server().context("no server selected")?;
        let contact = self.cur_contact().context("no contact selected")?;
        let username = self.username_of(&sid).context("not logged in")?;
        // Same precondition as send_file: without an authenticated WS the message lands only in the local DB while the UI shows a "sent" bubble — a silent loss
        if !self.session(&sid).map(|s| s.status()).unwrap_or(false) {
            anyhow::bail!("connection not ready, message not sent (wait for the reconnect to finish and try again)");
        }
        let key = self.priv_key(&sid).context("missing private key")?;
        let peer_pub = self.store.get_contact_public_key(&sid, &contact)?
            .context("no public key for the peer yet; add the contact first")?;

        let (ct, iv, tag, wrapped) = crypto::encrypt_text(content, &peer_pub)?;
        let msg_id = crypto::generate_msg_id();
        let ts = crypto::now_secs();
        let fields = crypto::build_message_fields(
            &msg_id, &contact, &username, ts, "", &ct, &iv, &tag, &wrapped, "", "", 0, "");
        let signature = crypto::sign_message_with_key(&key, &fields)?;

        let mut store_obj = json!({"from": username, "ciphertext": ct, "iv": iv, "tag": tag,
            "wrapped_key": wrapped, "msg_id": msg_id, "timestamp": ts, "original": content});
        // initial state: awaiting the server ack, which handle_ws_text turns into delivered / failed
        store::set_local_status(&mut store_obj, store::LOCAL_STATUS_SENT);
        let chat_key = store::make_chat_key(&username, &contact);
        self.store.insert_message(&sid, &chat_key, Some(&msg_id), &username,
            &store_obj.to_string(), &store::fmt_db_time(ts), content)?;

        let payload = json!({"to": contact, "ciphertext": ct, "iv": iv, "tag": tag,
            "msg_id": msg_id, "timestamp": ts, "wrapped_key": wrapped, "signature": signature});
        let msg = json!({"type":"send_message","payload":payload,"request_id":"s"}).to_string();
        let sent = if let Some(s) = self.session(&sid) {
            if let Some(tx) = s.tx.lock().unwrap().as_ref() {
                tx.send(Outbound::Text(msg)).is_ok()
            } else { false }
        } else { false };
        if !sent {
            // Could not queue onto the WS: mark it failed right away, so the bubble shows a failure instead of appearing successful
            self.set_local_status(&sid, &msg_id, store::LOCAL_STATUS_FAILED);
            self.emit(Event::Toast("send failed: the connection is down, the message was not sent".into()));
        }
        self.emit(Event::ChatUpdated { server_id: sid, contact });
        Ok(())
    }

    /// Add a contact. `nickname` is optional; when non-empty it is stored in local `contacts.nickname` as the display name.
    pub fn add_contact(self: &Arc<Self>, contact: String, nickname: String, req_id: String) {
        // lowercase everything: server IDs are lowercase hex, and mixed case would break later public-key lookups by `from`
        let contact = contact.trim().to_lowercase();
        if contact.is_empty() {
            self.emit(Event::AddContactResult {
                req_id, ok: false, message: "contact ID must not be empty".into() });
            return;
        }
        let nickname = nickname.trim().to_string();
        if nickname.chars().count() > MAX_NICKNAME_CHARS {
            self.emit(Event::AddContactResult {
                req_id, ok: false,
                message: format!("name too long (at most {MAX_NICKNAME_CHARS} characters)") });
            return;
        }
        // Pin the server at the call site, so a later server switch cannot add the contact to the wrong DB
        let sid = match self.cur_server() {
            Some(sid) => sid,
            None => {
                self.emit(Event::AddContactResult {
                    req_id, ok: false, message: "no server selected".into() });
                return;
            }
        };
        self.add_contact_on(&sid, contact, nickname, req_id);
    }

    /// Add a contact on a **specific server**: notification-center requests can come from any server, so the currently selected one must not be trusted.
    pub fn add_contact_on(
        self: &Arc<Self>,
        sid: &str,
        contact: String,
        nickname: String,
        req_id: String,
    ) {
        let sid = sid.to_string();
        let me = self.clone();
        thread::spawn(move || {
            // Run the existing fetch-and-verify-public-key flow first; write the nickname only after it succeeds
            let r = me.add_contact_inner(&sid, &contact, &nickname);
            let (ok, message) = match r {
                Ok(m) => (true, m),
                Err(e) => (false, format!("{e:#}")),
            };
            if ok {
                // Refresh presence immediately: otherwise the peer's online dot waits for the next `presence_snapshot` (~30s), which adding a friend does not trigger
                let _ = me.fetch_contacts_online(&sid);
            }
            me.emit(Event::AddContactResult { req_id, ok, message });
        });
    }

    /// Fetch "others added me one-way, I have not added back" (notification-center friend requests). Adding a contact is a
    /// one-way write, so only the server can compute this, and offline requests appear here too. `fetch_remote_public_key` verifies the `sha512(SPKI)[:10] == contact_id` binding locally.
    pub fn fetch_pending_contacts(self: &Arc<Self>, sid: &str) -> Result<Vec<String>> {
        let username = self.username_of(sid).context("not logged in")?;
        let key = self.priv_key(sid).context("missing private key")?;
        let signed = crypto::signed_request_body_with_key(&key, &[username.clone()])?;
        let mut body = json!({ "user_id": username });
        if let (Some(o), Some(sg)) = (body.as_object_mut(), signed.as_object()) {
            for (k, v) in sg {
                o.insert(k.clone(), v.clone());
            }
        }
        let res = self.rest(sid, "POST", "/contacts/pending_incoming", Some(body))?;
        if res.get("status").and_then(|v| v.as_str()) == Some("error") {
            anyhow::bail!(
                "{}",
                res.pointer("/error/message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("failed to fetch contact requests")
            );
        }
        Ok(res
            .pointer("/payload")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.get("user_id").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn fetch_remote_public_key(self: &Arc<Self>, sid: &str, contact: &str) -> Result<String> {
        let username = self.username_of(sid).context("not logged in")?;
        let key = self.priv_key(sid).context("missing private key")?;
        let mut body = json!({"user_id": username, "contact_user_id": contact});
        let signed = crypto::signed_request_body_with_key(
            &key, &[username.clone(), contact.to_string()])?;
        if let (Some(o), Some(s)) = (body.as_object_mut(), signed.as_object()) {
            for (k, v) in s { o.insert(k.clone(), v.clone()); }
        }
        let res = self.rest(sid, "POST", "/add_contact", Some(body))?;
        if res.get("status").and_then(|v| v.as_str()) == Some("error") {
            anyhow::bail!("{}", res.pointer("/error/message").and_then(|v| v.as_str())
                .unwrap_or("failed to fetch the public key"));
        }
        let pubkey = res.pointer("/payload/public_key").and_then(|v| v.as_str()).unwrap_or("");
        if pubkey.trim().is_empty() {
            anyhow::bail!("the server did not return the peer's public key");
        }
        if crypto::public_key_id(pubkey, 10)? != contact {
            anyhow::bail!("public key does not match the ID (possible man-in-the-middle); rejected");
        }
        Ok(pubkey.to_string())
    }

    fn add_contact_inner(self: &Arc<Self>, sid: &str, contact: &str, nickname: &str) -> Result<String> {
        // Write the contact only after fetching and verifying the peer key: public_key is the sole basis for later encryption and signature checks
        let pubkey = self.fetch_remote_public_key(sid, contact)?;
        self.store.set_contact_public_key(sid, contact, &pubkey)?;
        if !nickname.is_empty() {
            self.store.set_contact_nickname(sid, contact, nickname)?;
        }
        self.emit(Event::ServersChanged);
        Ok(if nickname.is_empty() {
            format!("added contact {contact}")
        } else {
            format!("added contact {nickname} ({contact})")
        })
    }

    /// Hard-delete a contact: contact + public key + that conversation's history + unread count (no server-side sync yet)
    pub fn delete_contact(self: &Arc<Self>, sid: &str, contact: &str) -> Result<()> {
        let username = self.username_of(sid).context("not logged in")?;
        let chat_key = store::make_chat_key(&username, contact);
        self.store.delete_contact(sid, contact, &chat_key)?;
        if let Some(s) = self.session(sid) {
            s.state.lock().unwrap().unread.remove(contact);
        }
        if self.cur_server().as_deref() == Some(sid)
            && self.cur_contact().as_deref() == Some(contact)
        {
            *self.current_contact.lock().unwrap() = None;
        }
        self.emit(Event::ServersChanged);
        Ok(())
    }

    /// Hard-delete a server: cascade-delete all local data and drop the connection (no server-side sync yet)
    pub fn delete_server(self: &Arc<Self>, sid: &str) -> Result<()> {
        self.deleted_servers.lock().unwrap().insert(sid.to_string());
        if let Some(s) = self.session(sid) {
            if let Some(tx) = s.tx.lock().unwrap().as_ref() {
                let _ = tx.send(Outbound::Stop);
            }
            s.ws_connected.store(false, Ordering::SeqCst);
        }
        self.store.delete_server(sid)?;
        self.priv_cache.lock().unwrap().remove(sid);
        let was_current = self.current_server.lock().unwrap().as_deref() == Some(sid);
        if was_current {
            *self.current_server.lock().unwrap() = None;
            *self.current_contact.lock().unwrap() = None;
        }
        self.emit(Event::ServersChanged);
        Ok(())
    }

    /// Rename a server (local display name only)
    pub fn rename_server(self: &Arc<Self>, sid: &str, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("name must not be empty");
        }
        self.store.rename_server(sid, name)?;
        if let Some(s) = self.session(sid) {
            s.set_name(name);
        }
        self.emit(Event::ServersChanged);
        Ok(())
    }

    /// Rename a contact (local display name only, never sent to the server); an empty string clears the nickname and falls back to the user_id.
    pub fn rename_contact(self: &Arc<Self>, sid: &str, contact: &str, nickname: &str) -> Result<()> {
        let nickname = nickname.trim();
        if nickname.chars().count() > MAX_NICKNAME_CHARS {
            anyhow::bail!("name too long (at most {MAX_NICKNAME_CHARS} characters)");
        }
        // confirm the contact exists, so the update cannot silently affect 0 rows
        let exists = self.store.get_contacts(sid)?
            .into_iter()
            .any(|c| c.username == contact && c.deleted == 0);
        if !exists {
            anyhow::bail!("contact does not exist: {contact}");
        }
        self.store.set_contact_nickname(sid, contact, nickname)?;
        self.emit(Event::ServersChanged);
        Ok(())
    }


    /// Send a file asynchronously: encrypt → upload ciphertext → WS notify (README §7.12). The target conversation is captured
    /// **at the call site**, because encryption+upload can take tens of seconds and a later `cur_contact()` read could send it to someone else.
    pub fn send_file(self: &Arc<Self>, path: PathBuf) {
        let sid = match self.cur_server() {
            Some(s) => s,
            None => { self.emit(Event::Toast("select a server first".into())); return; }
        };
        let contact = match self.cur_contact() {
            Some(c) => c,
            None => { self.emit(Event::Toast("select a contact first".into())); return; }
        };
        if !self.session(&sid).map(|s| s.status()).unwrap_or(false) {
            self.emit(Event::Toast("connection not ready, cannot send the file".into())); return;
        }
        let username = match self.username_of(&sid) {
            Some(u) => u,
            None => { self.emit(Event::Toast("not logged in to that server yet".into())); return; }
        };
        let me = self.clone();
        thread::spawn(move || {
            let name = path.file_name().map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".into());
            me.emit(Event::Toast(format!("sending file {name} ...")));
            match me.send_file_blocking(&sid, &username, &contact, &path) {
                Ok(msg) => me.emit(Event::Toast(msg)),
                Err(e) => me.emit(Event::Toast(format!("file send failed: {e:#}"))),
            }
        });
    }

    /// The actual send routine. `sid` / `username` / `contact` come from the call site; **no "current conversation" state is read here**.
    fn send_file_blocking(
        self: &Arc<Self>, sid: &str, username: &str, contact: &str, path: &Path,
    ) -> Result<String> {
        let key = self.priv_key(sid).context("missing private key")?;
        let peer_pub = self.store.get_contact_public_key(sid, contact)?
            .context("no public key for the peer yet; add the contact first")?;
        let name = path.file_name().map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".into());
        let size = std::fs::metadata(path).context("failed to stat the file")?.len();
        if size == 0 {
            anyhow::bail!("sending empty files is not supported yet");
        }
        if size > MAX_FILE_BYTES {
            anyhow::bail!("file too large (server limit {} MiB)", MAX_FILE_BYTES / 1024 / 1024);
        }

        // stream-encrypt into a temporary ciphertext file (AAD = file_id|size; the filename is encrypted separately)
        let file_id = crypto::generate_msg_id();
        let enc_path = temp_path("enc", &file_id);
        let _guard = TmpGuard(enc_path.clone());
        let header = crypto::encrypt_file_streaming(path, &name, &file_id, &peer_pub, &enc_path)?;
        if header.filename_enc_b64.len() > MAX_FILENAME_ENC_LEN {
            anyhow::bail!("filename too long ({} characters after encryption, server limit {})",
                          header.filename_enc_b64.len(), MAX_FILENAME_ENC_LEN);
        }

        let (ts, nonce, sig) = crypto::build_signed_params_with_key(
            &key,
            &[username.to_string(), file_id.clone(), contact.to_string(),
              header.filename_enc_b64.clone(), header.size.to_string(),
              header.sha256_hex.clone()],
        )?;
        let path_q = format!(
            "/upload_file?user_id={}&file_id={}&to={}&filename={}&size={}&sha256={}\
             &timestamp={}&nonce={}&signature={}",
            url_encode(username), url_encode(&file_id), url_encode(contact),
            url_encode(&header.filename_enc_b64), header.size, url_encode(&header.sha256_hex),
            ts, url_encode(&nonce), url_encode(&sig),
        );
        let (status, body) = self.rest_upload_file(sid, &path_q, &enc_path)?;
        let resp: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if status >= 400 || resp.get("status").and_then(|v| v.as_str()) != Some("ok") {
            anyhow::bail!("upload failed: {}", resp.pointer("/error/message")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| if status >= 400 { "HTTP error" } else { "rejected by the server" }));
        }

        // WS notification: 13-field signature + msg_type=file
        let msg_id = crypto::generate_msg_id();
        let msg_ts = crypto::now_secs();
        let fields = crypto::build_message_fields(
            &msg_id, contact, username, msg_ts, "file", "",
            &header.iv_b64, &header.tags_b64, &header.wrapped_key_b64,
            &file_id, &header.filename_enc_b64, header.size as i64, &header.sha256_hex);
        let signature = crypto::sign_message_with_key(&key, &fields)?;
        let payload = json!({
            "to": contact, "ciphertext": "", "iv": header.iv_b64, "tag": header.tags_b64,
            "msg_id": msg_id, "timestamp": msg_ts, "msg_type": "file",
            "file_id": file_id, "filename": header.filename_enc_b64,
            "size": header.size, "sha256": header.sha256_hex,
            "wrapped_key": header.wrapped_key_b64, "signature": signature,
        });
        let wire = json!({"type":"send_message","payload":payload,"request_id":"f"}).to_string();
        let sent = match self.session(sid) {
            Some(s) => match s.tx.lock().unwrap().as_ref() {
                Some(tx) => tx.send(Outbound::Text(wire)).is_ok(),
                None => false,
            },
            None => false,
        };
        if !sent {
            anyhow::bail!("WebSocket is not connected; the file was uploaded but the peer was not notified");
        }

        let mut store_obj = json!({
            "from": username, "msg_type": "file", "ciphertext": "",
            "iv": header.iv_b64, "tag": header.tags_b64, "msg_id": msg_id, "timestamp": msg_ts,
            "file_id": file_id, "filename": name, "size": header.size,
            "sha256": header.sha256_hex, "wrapped_key": header.wrapped_key_b64,
            "original": path.to_string_lossy(),
        });
        store::set_local_status(&mut store_obj, store::LOCAL_STATUS_SENT);
        let chat_key = store::make_chat_key(username, contact);
        self.store.insert_message(sid, &chat_key, Some(&msg_id), username,
            &store_obj.to_string(), &store::fmt_db_time(msg_ts), "")?;
        // The old code called to_string() on two &str here, discarding the result and making pointless copies; plain borrows suffice.
        self.emit(Event::ChatUpdated {
            server_id: sid.into(), contact: contact.into() });
        Ok(format!("file sent: {name}"))
    }

    /// Download and decrypt a received file in the background; retry up to `FILE_RECV_ATTEMPTS` with backoff, then write `file_error` (shown locally only — **the sender is never notified**).
    fn spawn_download_file(self: &Arc<Self>, sid: &str, sender: &str, p: Value) {
        let me = self.clone();
        let sid = sid.to_string();
        let sender = sender.to_string();
        thread::spawn(move || {
            let msg_id = p.get("msg_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            // mark "receiving", for the exit confirmation
            me.active_downloads.fetch_add(1, Ordering::SeqCst);
            let mut last_err: Option<String> = None;
            for attempt in 1..=FILE_RECV_ATTEMPTS {
                match me.download_incoming_file(&sid, &sender, &p) {
                    Ok(()) => {
                        me.active_downloads.fetch_sub(1, Ordering::SeqCst);
                        return;
                    }
                    Err(e) => {
                        let msg = format!("{e:#}");
                        crate::tui_log!("file receive failed (attempt {attempt}/{FILE_RECV_ATTEMPTS}): {msg}");
                        if attempt < FILE_RECV_ATTEMPTS {
                            me.emit(Event::Toast(format!(
                                "file receive failed, retrying ({attempt}/{FILE_RECV_ATTEMPTS}): {msg}")));
                            thread::sleep(Duration::from_secs(1u64 << (attempt - 1)));
                        }
                        last_err = Some(msg);
                    }
                }
            }
            me.active_downloads.fetch_sub(1, Ordering::SeqCst);
            // all retries failed: record the reason so the chat shows "receive failed"
            let detail = last_err.unwrap_or_else(|| "unknown reason".into());
            if !msg_id.is_empty() {
                match me.update_file_content_field(
                    &sid, &sender, &msg_id, "file_error", json!(detail))
                {
                    Ok(true) => {}
                    Ok(false) => crate::tui_log!(
                        "file receive failed but the message row is gone, cannot write back: {msg_id}"),
                    Err(e) => crate::tui_log!(
                        "failed to write back file_error: {e:#}"),
                }
            }
            me.emit(Event::ChatUpdated {
                server_id: sid.clone(), contact: sender.clone() });
            me.emit(Event::Toast(format!(
                "file receive failed (retried {FILE_RECV_ATTEMPTS} times): {detail}")));
        });
    }

    fn download_incoming_file(self: &Arc<Self>, sid: &str, sender: &str, p: &Value) -> Result<()> {
        let msg_id = s(p, "msg_id");
        let file_id = s(p, "file_id");
        let filename_enc = s(p, "filename");
        if msg_id.is_empty() || file_id.is_empty() || filename_enc.is_empty() {
            anyhow::bail!("file message is missing file_id/filename/msg_id");
        }
        let size = p.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let sha_expected = s(p, "sha256");
        let key = self.priv_key(sid).context("missing private key")?;
        let file_key = crypto::rsa_unwrap_key_with_key(s(p, "wrapped_key"), &key)?;
        let raw_name = crypto::decrypt_filename_with_file_key(&file_key, filename_enc)?;
        let name = safe_file_name(&raw_name);

        // Write the plaintext filename first so the UI shows the right name early; the "row hit" flag does not affect the download/retry logic
        let _ = self.update_file_content_field(
            sid, sender, msg_id, "plain_filename", json!(name))?;
        self.emit(Event::ChatUpdated { server_id: sid.into(), contact: sender.into() });

        // Resumable ciphertext download. Chunks live in `received_files/.part/`, deliberately not the system temp dir (which may be cleaned); the byte count also goes into the message JSON.
        let username = self.username_of(sid).context("not logged in")?;
        let part_dir = partial_dir();
        std::fs::create_dir_all(&part_dir).context("failed to create the partial directory")?;
        let part_path = part_dir.join(format!("{file_id}.enc"));

        let mut resume_from = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
        if resume_from > size {
            // a chunk larger than the target is a corrupted/mismatched leftover; start over
            let _ = std::fs::remove_file(&part_path);
            resume_from = 0;
        }
        if resume_from > 0 {
            crate::tui_log!("detected an unfinished chunk set, resuming {file_id} from {resume_from}/{size} bytes");
        }

        let complete = size > 0 && resume_from >= size;
        let mut last_report = std::time::Instant::now();
        let mut last_reported = resume_from;
        let mut attempt = 0u32;
        while !complete {
            attempt += 1;
            if attempt > 8 {
                anyhow::bail!("download incomplete (tried {attempt} times, {resume_from}/{size} bytes)");
            }
            // re-sign on every resume (REST signatures have a 5-minute window, so long downloads must regenerate them)
            let (ts, nonce, sig) = crypto::build_signed_params_with_key(
                &key, &[username.clone(), file_id.to_string()])?;
            let path = format!("/download_file/{}?user_id={}&timestamp={}&nonce={}&signature={}",
                url_encode(file_id), url_encode(&username), ts,
                url_encode(&nonce), url_encode(&sig));

            let (status, body) = self.rest_download_file(sid, &path, &part_path, resume_from)?;
            if status != 200 && status != 206 {
                anyhow::bail!("download failed: HTTP {status}: {}",
                              String::from_utf8_lossy(&body).trim());
            }
            let now_len = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
            if now_len > size {
                anyhow::bail!("downloaded content exceeds the declared size ({now_len} > {size}), aborted");
            }
            resume_from = now_len;
            if now_len >= size {
                break;
            }
            if last_report.elapsed() >= Duration::from_secs(2) && now_len != last_reported {
                last_report = std::time::Instant::now();
                last_reported = now_len;
                let pct = (now_len * 100 / size.max(1)) as u64;
                let _ = self.update_file_content_field(
                    sid, sender, msg_id, "file_progress", json!(pct));
                self.emit(Event::ChatUpdated {
                    server_id: sid.into(), contact: sender.into() });
            }
            crate::tui_log!("download interrupted, {now_len}/{size} bytes, preparing to resume");
        }

        // Phase 2: decrypt + SHA-256 check (local, no network)
        let plain_tmp = temp_path("plain", file_id);
        let _g = TmpGuard(plain_tmp.clone());
        crypto::decrypt_file_streaming(
            &part_path, &plain_tmp, &key, file_id, size,
            s(p, "iv"), s(p, "tag"), s(p, "wrapped_key"), &sha_expected)?;

        let dir = received_files_dir();
        std::fs::create_dir_all(&dir).context("failed to create the receive directory")?;
        let dest = unique_dest(&dir, &name);
        if std::fs::rename(&plain_tmp, &dest).is_err() {
            std::fs::copy(&plain_tmp, &dest).context("failed to save the file")?;
            let _ = std::fs::remove_file(&plain_tmp);
        }
        // the plaintext is on disk and SHA-256 passed, so the chunks can go
        let _ = std::fs::remove_file(&part_path);

        let _ = self.update_file_content_field(
            sid, sender, msg_id, "original", json!(dest.to_string_lossy()))?;
        let _ = self.update_file_content_field(
            sid, sender, msg_id, "file_progress", Value::Null)?;
        self.emit(Event::ChatUpdated { server_id: sid.into(), contact: sender.into() });
        self.emit(Event::Toast(format!("file received: {} → {}", name, dest.display())));
        Ok(())
    }

    /// Update one field of a file message's content JSON (plain_filename / original / file_error).
    /// `Ok(false)` means the row is gone (conversation/message deleted) and should be logged, not dropped; always returning `Ok(())` left bubbles stuck at "receiving…".
    fn update_file_content_field(
        &self, sid: &str, sender: &str, msg_id: &str, field: &str, value: Value,
    ) -> Result<bool> {
        let username = self.username_of(sid).unwrap_or_default();
        let chat_key = store::make_chat_key(&username, sender);
        let Some(row) = self.store.get_message_by_msg_id(sid, &chat_key, msg_id)? else {
            return Ok(false);
        };
        let mut obj: Value = serde_json::from_str(&row.content).unwrap_or_else(|_| json!({}));
        if let Some(map) = obj.as_object_mut() {
            map.insert(field.to_string(), value);
        }
        self.store.update_message_content_by_msg_id(sid, &chat_key, msg_id, &obj.to_string())?;
        Ok(true)
    }

    /// Rewrite the `local_status` of a message this machine sent. Acks carry only `(msg_id, to)` and no sender, so the row is
    /// found by `(server_id, msg_id)`. If the conversation is open, only mark it dirty — **never `reload_chat`**, which would truncate scrolled-back history and jump the viewport to the bottom.
    fn set_local_status(&self, sid: &str, msg_id: &str, status: &str) {
        let row = match self.store.find_message_by_msg_id(sid, msg_id) {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                crate::tui_log!("failed to update the send status (DB lookup): {e:#}");
                return;
            }
        };
        let mut obj: Value = serde_json::from_str(&row.content).unwrap_or_else(|_| json!({}));
        store::set_local_status(&mut obj, status);
        if let Err(e) = self.store
            .update_message_content_by_sid_msg_id(sid, msg_id, &obj.to_string())
        {
            crate::tui_log!("failed to update the send status (DB write): {e:#}");
            return;
        }

        if self.cur_server().as_deref() == Some(sid)
            && self.cur_contact().as_deref() == Some(row.sender.as_str())
        {
            self.emit(Event::ChatUpdated { server_id: sid.into(), contact: row.sender });
        }
    }

    fn apply_send_ack(&self, sid: &str, msg_id: &str, status: &str, err: Option<&str>) {
        self.set_local_status(sid, msg_id, status);
        if status == store::LOCAL_STATUS_FAILED {
            crate::tui_log!("server rejected message {msg_id}: {}", err.unwrap_or("unknown reason"));
        }
    }

    pub fn load_messages(&self, sid: &str, contact: &str, limit: i64)
        -> Result<(Vec<store::MessageRow>, i64)>
    {
        let username = self.username_of(sid).unwrap_or_default();
        let chat_key = store::make_chat_key(&username, contact);
        let total = self.store.count_messages(sid, &chat_key)?;
        if total == 0 { return Ok((vec![], 0)); }
        let limit = limit.min(total);
        Ok((self.store.get_messages(sid, &chat_key, limit, total - limit)?, total))
    }

    /// Lazy-load older messages: take the newest `count` rows with `id < before_id` (no full table read)
    pub fn load_earlier(&self, sid: &str, contact: &str, before_id: i64, count: i64)
        -> Result<Vec<store::MessageRow>>
    {
        let username = self.username_of(sid).unwrap_or_default();
        let chat_key = store::make_chat_key(&username, contact);
        self.store.get_messages_before(sid, &chat_key, before_id, count)
    }
}

struct TmpGuard(PathBuf);
impl Drop for TmpGuard {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

fn temp_path(tag: &str, id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("mcrt_{}_{}_{}.tmp", tag, id, std::process::id()))
}

/// Minimal URL percent-encoding for query parameters
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Safe filename: keep only the basename and reject empty/relative paths
fn safe_file_name(name: &str) -> String {
    let name = name.replace('\\', "/");
    let base = name.rsplit('/').next().unwrap_or("").trim();
    let base = if base.is_empty() || base == "." || base == ".." {
        "file".to_string()
    } else {
        base.to_string()
    };
    // most filesystems cap a single name at 255 bytes; truncate to 200 with headroom, on a UTF-8 boundary
    truncate_utf8_bytes(&base, 200)
}

fn truncate_utf8_bytes(s: &str, max: usize) -> String {
    if s.len() <= max { return s.to_string(); }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    s[..end].to_string()
}

/// Received-files directory: `received_files/` next to the executable (Rust client convention)
fn received_files_dir() -> PathBuf {
    let base = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("received_files")
}

/// Chunk directory for unfinished downloads: `<program dir>/received_files/.part/`. Deliberately **not** the system temp dir, which may be cleaned by the system or the user and would break resumption.
fn partial_dir() -> PathBuf {
    received_files_dir().join(".part")
}

/// Append (1), (2)… for same-named files to avoid overwriting
fn unique_dest(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() { return first; }
    let p = Path::new(name);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    for i in 1..=100000 {
        let cand = dir.join(format!("{stem}({i}){ext}"));
        if !cand.exists() { return cand; }
    }
    dir.join(format!("{stem}({}){ext}", crypto::chrono_now_ms()))
}

fn s<'a>(p: &'a Value, k: &str) -> &'a str {
    p.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

pub fn fmt_pin(pin: &str) -> String {
    pin.as_bytes().chunks(8)
        .map(|c| String::from_utf8_lossy(c).to_string())
        .collect::<Vec<_>>().join(" ")
}

/// Replace the online set wholesale from the server snapshot (pure, so self-healing is testable); IDs outside `known` are ignored, `false` dropped, `true` kept.
fn merge_presence_snapshot(
    _current: &HashSet<String>,
    snapshot: &serde_json::Map<String, Value>,
    known: &HashSet<String>,
) -> HashSet<String> {
    snapshot.iter()
        .filter(|(id, v)| v.as_bool().unwrap_or(false) && known.contains(*id))
        .map(|(id, _)| id.clone())
        .collect()
}

#[cfg(test)]
mod file_util_tests {
    use super::*;

    #[test]
    /// The snapshot must **replace** the online set wholesale, correcting drift caused by lost incremental pushes.
    #[test]
    fn presence_snapshot_replaces_and_heals() {
        use super::{merge_presence_snapshot};
        use serde_json::json;
        use std::collections::HashSet;

        let known: HashSet<String> = ["b", "c", "d"].iter().map(|s| s.to_string()).collect();
        let snap = |v: serde_json::Value| -> serde_json::Map<String, serde_json::Value> {
            v.as_object().unwrap().clone()
        };

        // ① falsely online (B's offline push was lost) → B=false in the snapshot must drop it
        let stale: HashSet<String> = ["b", "c"].iter().map(|s| s.to_string()).collect();
        let got = merge_presence_snapshot(
            &stale, &snap(json!({"b": false, "c": true, "d": false})), &known);
        assert_eq!(got, ["c".to_string()].into_iter().collect::<HashSet<_>>(),
            "b (now offline) must be dropped, c kept");

        // ② falsely offline (D's online push was lost) → D=true in the snapshot must add it back
        let stale: HashSet<String> = HashSet::new();
        let got = merge_presence_snapshot(
            &stale, &snap(json!({"b": true, "c": false, "d": true})), &known);
        assert_eq!(got, ["b".to_string(), "d".to_string()].into_iter().collect::<HashSet<_>>(),
            "b and d must be added back");

        // ③ an unknown ID in the snapshot (a contact I never added) → ignore
        let got = merge_presence_snapshot(
            &HashSet::new(), &snap(json!({"zzz": true, "b": true})), &known);
        assert_eq!(got, ["b".to_string()].into_iter().collect::<HashSet<_>>(),
            "unknown IDs must not enter the set");

        let stale: HashSet<String> = ["b", "c"].iter().map(|s| s.to_string()).collect();
        let got = merge_presence_snapshot(&stale, &snap(json!({})), &known);
        assert!(got.is_empty(), "an empty snapshot must clear the set");

        // ⑤ non-boolean → treated as false (defensive against malformed payloads)
        let got = merge_presence_snapshot(
            &HashSet::new(), &snap(json!({"b": "yes"})), &known);
        assert!(got.is_empty(), "non-boolean values must be treated as offline");
    }

    fn test_safe_file_name() {
        assert_eq!(safe_file_name("a/b/c.txt"), "c.txt");
        assert_eq!(safe_file_name("a\\b\\c.txt"), "c.txt");
        assert_eq!(safe_file_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_file_name(".."), "file");
        assert_eq!(safe_file_name(""), "file");
    }

    #[test]
    fn test_safe_file_name_long() {
        let long = "x".repeat(300);
        let n = safe_file_name(&long);
        assert!(n.len() <= 200, "truncated len = {}", n.len());
        assert!(n.chars().all(|c| c == 'x'));
    }

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("a+b/c="), "a%2Bb%2Fc%3D");
        assert_eq!(url_encode("abcXYZ09-_.~"), "abcXYZ09-_.~");
    }

    #[test]
    fn test_unique_dest() {
        let dir = std::env::temp_dir().join(format!("mcrt_test_{}", crypto::chrono_now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let dest = unique_dest(&dir, "a.txt");
        assert!(dest.ends_with("a(1).txt"), "got {dest:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
