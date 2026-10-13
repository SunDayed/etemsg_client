//! SQLCipher storage layer. Schema and semantics match Python `database.py` + `config.py`, so `etemsg.db` files written by the Python client are readable and writable.

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::sync::Mutex;

/// Schema version written to `PRAGMA user_version` (for external tools). Clients never read it or migrate: one schema only, all
/// tables `IF NOT EXISTS`, so an old DB missing a column fails to open — no migration code, no old-DB-only bugs.
pub const SCHEMA_VERSION: i64 = 4;

/// Valid TCP port range (`api_port` is an INTEGER in the DB and callers convert it to u16).
pub const PORT_MIN: i64 = 1;
pub const PORT_MAX: i64 = 65535;

// Local send state (message content JSON field `local_status`). Acks carry no sender and are not persisted, so the client
// tracks delivery itself; `delivered` means the server enqueued it, not that the peer got it: sent / queued (offline queue) /
// delivered (pushed live) / failed (WS down or rejected) / unknown (leftover `sent`, ack lost). queued and delivered are success; only failed/unknown are flagged (see `ui.rs::message_lines`).
pub const LOCAL_STATUS_KEY: &str = "local_status";
pub const LOCAL_STATUS_SENT: &str = "sent";
/// Server accepted it into the peer's offline queue (peer offline)
pub const LOCAL_STATUS_QUEUED: &str = "queued";
pub const LOCAL_STATUS_DELIVERED: &str = "delivered";
pub const LOCAL_STATUS_FAILED: &str = "failed";
/// Leftover "awaiting ack" message from a previous run; the ack was lost, so it is downgraded to this on startup.
pub const LOCAL_STATUS_UNKNOWN: &str = "unknown";

/// Write the local send status into a message content JSON object.
pub fn set_local_status(obj: &mut Value, status: &str) {
    if let Some(m) = obj.as_object_mut() {
        m.insert(LOCAL_STATUS_KEY.to_string(), Value::String(status.to_string()));
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub host: String,
    pub api_port: i64,
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub server_id: String,
    pub username: String,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub server_id: String,
    pub username: String,
    pub nickname: Option<String>,
    pub public_key: Option<String>,
    pub deleted: i64,
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub id: i64,
    pub server_id: String,
    pub chat_key: String,
    pub msg_id: Option<String>,
    pub sender: String,
    pub content: String,
    pub time: String,
    pub plaintext: String,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Open (creating if needed) the database. `master_key = None` uses plaintext SQLite.
    pub fn open(path: &str, master_key: Option<&str>) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("cannot open database {path}"))?;
        if let Some(key) = master_key {
            // The key must be passed as text; a BLOB is treated by SQLCipher as a raw key
            conn.pragma_update(None, "key", key)
                .context("PRAGMA key failed (wrong master key or corrupt database)")?;
        }
        // SQLCipher logs to stderr by default and `PRAGMA key` triggers sqlcipher_activate() (once), which sets the log target;
        // so `PRAGMA cipher_log = off` must come **after** it, leaving errors to surface via rusqlite for the UI.
        let _ = conn.execute_batch("PRAGMA cipher_log = off;");
        conn.pragma_update(None, "journal_mode", "WAL").ok();
        conn.pragma_update(None, "busy_timeout", 5000).ok();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS servers (
                 id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
                 api_port INTEGER NOT NULL, cert_pin TEXT);
             CREATE TABLE IF NOT EXISTS identities (
                 server_id TEXT NOT NULL, username TEXT NOT NULL,
                 private_key TEXT NOT NULL, public_key TEXT NOT NULL,
                 nickname TEXT, PRIMARY KEY (server_id, username));
             CREATE TABLE IF NOT EXISTS app_state (
                 key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS contacts (
                 server_id TEXT NOT NULL, username TEXT NOT NULL, nickname TEXT,
                 public_key TEXT, deleted INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (server_id, username));
             CREATE INDEX IF NOT EXISTS idx_contacts_server ON contacts(server_id);
             CREATE TABLE IF NOT EXISTS chat_messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL,
                 chat_key TEXT NOT NULL, msg_id TEXT, sender TEXT NOT NULL,
                 content TEXT NOT NULL, time TEXT NOT NULL,
                 plaintext TEXT NOT NULL DEFAULT '');
             CREATE INDEX IF NOT EXISTS idx_chat_server_key
                 ON chat_messages(server_id, chat_key);
             CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_server_msg
                 ON chat_messages(server_id, chat_key, msg_id);
             CREATE TABLE IF NOT EXISTS unread (
                 server_id TEXT NOT NULL, username TEXT NOT NULL,
                 count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (server_id, username));
             CREATE TABLE IF NOT EXISTS meta (
                 server_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
                 PRIMARY KEY (server_id, key));

             -- ─────────── Group (MLS) local tables ───────────
             -- Fully separate from 1v1: no chat_key, no shared unread counters;
             -- Everything uses CREATE TABLE IF NOT EXISTS; older schemas are not migrated.

             CREATE TABLE IF NOT EXISTS group_conversations (
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 name_enc BLOB,
                 my_role TEXT NOT NULL DEFAULT 'member',
                 current_epoch INTEGER NOT NULL DEFAULT 0,
                 joined_epoch INTEGER NOT NULL DEFAULT 0,
                 min_seq INTEGER NOT NULL DEFAULT 0,
                 joined_at TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (server_id, group_id));

             CREATE TABLE IF NOT EXISTS group_messages (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 seq INTEGER NOT NULL,
                 msg_id TEXT NOT NULL DEFAULT '',
                 sender TEXT NOT NULL,
                 plaintext TEXT NOT NULL DEFAULT '',
                 time TEXT NOT NULL DEFAULT '',
                 epoch INTEGER NOT NULL DEFAULT 0,
                 state TEXT NOT NULL DEFAULT 'ok',
                 UNIQUE (server_id, group_id, seq));

             CREATE TABLE IF NOT EXISTS group_cursor (
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 last_seq INTEGER NOT NULL DEFAULT 0,
                 min_seq INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (server_id, group_id));

             CREATE TABLE IF NOT EXISTS group_unread (
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 count INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (server_id, group_id));

             -- MLS state blob: the most sensitive data here; only stored in this encrypted DB, never logged
             CREATE TABLE IF NOT EXISTS mls_private_state (
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 epoch INTEGER NOT NULL DEFAULT 0,
                 state_blob BLOB NOT NULL,
                 signer_blob BLOB NOT NULL,
                 updated_at TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (server_id, group_id));

             CREATE TABLE IF NOT EXISTS mls_members (
                 server_id TEXT NOT NULL,
                 group_id TEXT NOT NULL,
                 user_id TEXT NOT NULL,
                 role TEXT NOT NULL DEFAULT 'member',
                 joined_epoch INTEGER NOT NULL DEFAULT 0,
                 -- In-group nickname: travels inside the MLS credential, invisible to the server
                 nickname TEXT NOT NULL DEFAULT '',
                 PRIMARY KEY (server_id, group_id, user_id));
             CREATE INDEX IF NOT EXISTS idx_group_messages ON group_messages(server_id, group_id, seq);",
        )?;
        // No migration logic by design: one schema, no legacy compatibility; an old DB missing a column fails to open (see the file header).
        conn.pragma_update(None, "user_version", SCHEMA_VERSION).ok();
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Fold the WAL into the main DB and truncate `-wal`; failure is non-fatal (the data stays in the WAL), so callers just log it.
    ///
    /// **Why explicit**: `main` exits via `std::process::exit()`, skipping destructors, and the WS/group threads hold `Arc<Store>`
    /// without ever being joined — SQLite never sees the last close, so auto-checkpoint never runs and the main DB stays stale
    /// while data piles up in `-wal`. Not data loss (the WAL replays on reopen), but copying only `etemsg.db` loses everything.
    pub fn checkpoint(&self) -> Result<()> {
        let c = self.conn();
        // TRUNCATE needs an exclusive lock and may report busy while other connections read; fall back to PASSIVE (write back as much as possible).
        let row = c
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
            })
            .optional()?;
        match row {
            Some((0, _, _)) => Ok(()),
            _ => {
                c.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
                })
                .optional()?;
                Ok(())
            }
        }
    }

    pub fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get_servers(&self) -> Result<Vec<Server>> {
        let c = self.conn();
        let mut st = c.prepare("SELECT id,name,host,api_port FROM servers ORDER BY rowid")?;
        let rows = st.query_map([], |r| {
            Ok(Server { id: r.get(0)?, name: r.get(1)?, host: r.get(2)?, api_port: r.get(3)? })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Insert a server. The port is clamped to 1..=65535: `api_port` is an INTEGER, and an out-of-range value would be silently truncated by `as u16` on the read side and connect to the wrong port.
    pub fn insert_server(&self, id: &str, name: &str, host: &str, port: i64) -> Result<()> {
        let port = port.clamp(PORT_MIN, PORT_MAX);
        self.conn().execute(
            "INSERT INTO servers(id,name,host,api_port) VALUES(?,?,?,?)",
            params![id, name, host, port],
        )?;
        Ok(())
    }

    pub fn get_cert_pin(&self, sid: &str) -> Result<Option<String>> {
        // cert_pin is NULL before the first connection, so read it as Option<String>; otherwise rusqlite fails with "Invalid column type Null at index: 0".
        Ok(self
            .conn()
            .query_row("SELECT cert_pin FROM servers WHERE id=?",
                       params![sid], |r| r.get::<_, Option<String>>(0))
            .optional()?
            .flatten())
    }

    pub fn set_cert_pin(&self, sid: &str, pin: &str) -> Result<()> {
        self.conn()
            .execute("UPDATE servers SET cert_pin=? WHERE id=?", params![pin, sid])?;
        Ok(())
    }

    pub fn get_identity(&self, sid: &str, username: &str) -> Result<Option<Identity>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT server_id,username,private_key,public_key
                   FROM identities WHERE server_id=? AND username=?",
                params![sid, username],
                |r| {
                    Ok(Identity {
                        server_id: r.get(0)?,
                        username: r.get(1)?,
                        private_key: r.get(2)?,
                        public_key: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn upsert_identity(&self, i: &Identity) -> Result<()> {
        self.conn().execute(
            "INSERT INTO identities(server_id,username,private_key,public_key)
             VALUES(?,?,?,?)
             ON CONFLICT(server_id,username) DO UPDATE SET
               private_key=excluded.private_key, public_key=excluded.public_key",
            params![i.server_id, i.username, i.private_key, i.public_key],
        )?;
        Ok(())
    }

    pub fn get_state(&self, key: &str) -> Result<Option<String>> {
        let raw: Option<String> = self
            .conn()
            .query_row("SELECT value FROM app_state WHERE key=?", params![key], |r| r.get(0))
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str::<String>(&s).ok()))
    }

    pub fn set_state(&self, key: &str, value: &str) -> Result<()> {
        let enc = serde_json::to_string(value)?;
        self.conn().execute(
            "INSERT INTO app_state(key,value) VALUES(?,?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, enc],
        )?;
        Ok(())
    }

    pub fn get_contacts(&self, sid: &str) -> Result<Vec<Contact>> {
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT server_id,username,nickname,public_key,deleted FROM contacts
              WHERE server_id=? ORDER BY rowid")?;
        let rows = st.query_map(params![sid], |r| {
            Ok(Contact {
                server_id: r.get(0)?, username: r.get(1)?, nickname: r.get(2)?,
                public_key: r.get(3)?, deleted: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_contact_public_key(&self, sid: &str, username: &str, pem: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO contacts(server_id,username,public_key,deleted) VALUES(?,?,?,0)
             ON CONFLICT(server_id,username) DO UPDATE SET
               public_key=excluded.public_key, deleted=0",
            params![sid, username, pem],
        )?;
        Ok(())
    }

    /// Hard-delete a contact: the contact row + that conversation's chat history + unread count (no server-side sync yet).
    pub fn delete_contact(&self, sid: &str, username: &str, chat_key: &str) -> Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        tx.execute("DELETE FROM contacts WHERE server_id=? AND username=?",
                   params![sid, username])?;
        tx.execute("DELETE FROM unread WHERE server_id=? AND username=?",
                   params![sid, username])?;
        tx.execute("DELETE FROM chat_messages WHERE server_id=? AND chat_key=?",
                   params![sid, chat_key])?;
        tx.commit()?;
        Ok(())
    }

    /// Hard-delete a server, cascading to its identities, contacts, chat history, unread counts, token and current-user state (no server-side sync yet).
    pub fn delete_server(&self, sid: &str) -> Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        tx.execute("DELETE FROM servers WHERE id=?", params![sid])?;
        tx.execute("DELETE FROM identities WHERE server_id=?", params![sid])?;
        tx.execute("DELETE FROM contacts WHERE server_id=?", params![sid])?;
        tx.execute("DELETE FROM chat_messages WHERE server_id=?", params![sid])?;
        tx.execute("DELETE FROM unread WHERE server_id=?", params![sid])?;
        tx.execute("DELETE FROM meta WHERE server_id=?", params![sid])?;
        tx.execute("DELETE FROM app_state WHERE key=?", params![format!("current_user_{sid}")])?;
        // older versions stored the current server in app_state; clear it if it points at the deleted server
        tx.execute("DELETE FROM app_state WHERE key='current_server' AND value=?",
                   params![serde_json::to_string(sid)?])?;
        tx.commit()?;
        Ok(())
    }

    pub fn rename_server(&self, sid: &str, name: &str) -> Result<()> {
        self.conn().execute("UPDATE servers SET name=? WHERE id=?", params![name, sid])?;
        Ok(())
    }

    /// Set a contact nickname (local display name only). An empty string clears it and falls back to showing the user_id.
    pub fn set_contact_nickname(&self, sid: &str, username: &str, nickname: &str) -> Result<()> {
        let value: Option<&str> = if nickname.trim().is_empty() { None } else { Some(nickname) };
        self.conn().execute(
            "UPDATE contacts SET nickname=? WHERE server_id=? AND username=?",
            params![value, sid, username])?;
        Ok(())
    }

    pub fn get_contact_public_key(&self, sid: &str, username: &str) -> Result<Option<String>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT public_key FROM contacts WHERE server_id=? AND username=?",
                params![sid, username], |r| r.get(0))
            .optional()?
            .flatten())
    }

    /// Delete contacts with no public key plus their leftover unread counts; returns the row count.
    /// Older versions wrote such rows when merging server-side contacts on login (no key) or when `/add_contact` returned none; they are unusable and purged at startup.
    pub fn purge_keyless_contacts(&self) -> Result<usize> {
        let c = self.conn();
        let n = c.execute(
            "DELETE FROM contacts WHERE public_key IS NULL OR TRIM(public_key) = ''", [])?;
        // also drop unread counts that no longer map to a usable contact, so stale IDs do not linger
        c.execute(
            "DELETE FROM unread WHERE NOT EXISTS (
                 SELECT 1 FROM contacts ct
                  WHERE ct.server_id = unread.server_id
                    AND ct.username = unread.username
                    AND ct.deleted = 0
                    AND ct.public_key IS NOT NULL
                    AND TRIM(ct.public_key) <> '')",
            [])?;
        Ok(n)
    }

    /// Insert a message; `INSERT OR IGNORE` returns false for a redelivered `(server_id, chat_key, msg_id)`, deduping atomically against the offline-fetch/WS race.
    pub fn insert_message(
        &self, sid: &str, chat_key: &str, msg_id: Option<&str>, sender: &str,
        content: &str, time: &str, plaintext: &str,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO chat_messages(server_id,chat_key,msg_id,sender,content,time,plaintext)
             VALUES(?,?,?,?,?,?,?)",
            params![sid, chat_key, msg_id, sender, content, time, plaintext],
        )?;
        Ok(n > 0)
    }

    pub fn count_messages(&self, sid: &str, chat_key: &str) -> Result<i64> {
        Ok(self.conn().query_row(
            "SELECT count(*) FROM chat_messages WHERE server_id=? AND chat_key=?",
            params![sid, chat_key], |r| r.get(0))?)
    }

    pub fn get_messages(&self, sid: &str, chat_key: &str, limit: i64, offset: i64) -> Result<Vec<MessageRow>> {
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT id,server_id,chat_key,msg_id,sender,content,time,plaintext
               FROM chat_messages WHERE server_id=? AND chat_key=?
              ORDER BY id ASC LIMIT ? OFFSET ?")?;
        let rows = st.query_map(params![sid, chat_key, limit, offset], |r| {
            Ok(MessageRow {
                id: r.get(0)?, server_id: r.get(1)?, chat_key: r.get(2)?, msg_id: r.get(3)?,
                sender: r.get(4)?, content: r.get(5)?, time: r.get(6)?, plaintext: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Lazy load: the newest `limit` rows with `id < before_id`, returned in ascending id order (old → new).
    pub fn get_messages_before(
        &self, sid: &str, chat_key: &str, before_id: i64, limit: i64,
    ) -> Result<Vec<MessageRow>> {
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT id,server_id,chat_key,msg_id,sender,content,time,plaintext
               FROM chat_messages WHERE server_id=? AND chat_key=? AND id < ?
              ORDER BY id DESC LIMIT ?")?;
        let rows = st.query_map(params![sid, chat_key, before_id, limit], |r| {
            Ok(MessageRow {
                id: r.get(0)?, server_id: r.get(1)?, chat_key: r.get(2)?, msg_id: r.get(3)?,
                sender: r.get(4)?, content: r.get(5)?, time: r.get(6)?, plaintext: r.get(7)?,
            })
        })?;
        let mut v = rows.collect::<Result<Vec<_>, _>>()?;
        v.reverse();
        Ok(v)
    }

    /// Update a message's content JSON by msg_id (file messages use this to write plain_filename / original).
    pub fn update_message_content_by_msg_id(
        &self, sid: &str, chat_key: &str, msg_id: &str, content: &str,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE chat_messages SET content=? WHERE server_id=? AND chat_key=? AND msg_id=?",
            params![content, sid, chat_key, msg_id])?;
        Ok(())
    }

    /// Locate a message by `(server_id, msg_id)` only (first row by id when duplicated): acks carry just `msg_id`/`to` and no sender,
    /// so no exact local `chat_key` can be rebuilt (group chats / multiple identities), while the UUID is unique within one server.
    pub fn find_message_by_msg_id(&self, sid: &str, msg_id: &str) -> Result<Option<MessageRow>> {
        Ok(self.conn().query_row(
            "SELECT id,server_id,chat_key,msg_id,sender,content,time,plaintext
               FROM chat_messages WHERE server_id=? AND msg_id=? ORDER BY id LIMIT 1",
            params![sid, msg_id],
            |r| Ok(MessageRow {
                id: r.get(0)?, server_id: r.get(1)?, chat_key: r.get(2)?, msg_id: r.get(3)?,
                sender: r.get(4)?, content: r.get(5)?, time: r.get(6)?, plaintext: r.get(7)?,
            })).optional()?)
    }

    /// Update content JSON by `(server_id, msg_id)` (no `chat_key` needed); used to rewrite local send state from server acks.
    pub fn update_message_content_by_sid_msg_id(
        &self, sid: &str, msg_id: &str, content: &str,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE chat_messages SET content=? WHERE server_id=? AND msg_id=?",
            params![content, sid, msg_id])?;
        Ok(())
    }

    /// List file messages not yet fully received (`msg_type='file'` with no `original`) for resume; `file_error` is ignored, since retrying with chunks present is idempotent.
    pub fn list_pending_file_downloads(&self, sid: &str) -> Result<Vec<MessageRow>> {
        let c = self.conn();
        let mut st = c.prepare(
            "SELECT id,server_id,chat_key,msg_id,sender,content,time,plaintext
               FROM chat_messages
              WHERE server_id = ?1
                AND json_extract(content, '$.msg_type') = 'file'
                AND (json_extract(content, '$.original') IS NULL
                     OR json_extract(content, '$.original') = '')
              ORDER BY id DESC LIMIT 50")?;
        let rows = st.query_map(params![sid], |r| {
            Ok(MessageRow {
                id: r.get(0)?, server_id: r.get(1)?, chat_key: r.get(2)?, msg_id: r.get(3)?,
                sender: r.get(4)?, content: r.get(5)?, time: r.get(6)?, plaintext: r.get(7)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

/// Rewrite every message with `local_status='sent'` to `status`; returns the number of affected rows.
    /// SQLite's built-in JSON1 (`json_extract` / `json_set`) avoids parsing rows in Rust.
    pub fn downgrade_pending_sends(&self, status: &str) -> Result<usize> {
        let n = self.conn().execute(
            "UPDATE chat_messages
                SET content = json_set(content, '$.local_status', ?1)
              WHERE json_extract(content, '$.local_status') = ?2",
            params![status, LOCAL_STATUS_SENT])?;
        Ok(n)
    }

    pub fn get_message_by_msg_id(&self, sid: &str, chat_key: &str, msg_id: &str) -> Result<Option<MessageRow>> {        Ok(self.conn().query_row(
            "SELECT id,server_id,chat_key,msg_id,sender,content,time,plaintext
               FROM chat_messages WHERE server_id=? AND chat_key=? AND msg_id=? LIMIT 1",
            params![sid, chat_key, msg_id],
            |r| Ok(MessageRow {
                id: r.get(0)?, server_id: r.get(1)?, chat_key: r.get(2)?, msg_id: r.get(3)?,
                sender: r.get(4)?, content: r.get(5)?, time: r.get(6)?, plaintext: r.get(7)?,
            })).optional()?)
    }

    pub fn get_unread(&self, sid: &str) -> Result<std::collections::HashMap<String, i64>> {
        let c = self.conn();
        let mut st = c.prepare("SELECT username,count FROM unread WHERE server_id=?")?;
        let rows = st.query_map(params![sid], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut m = std::collections::HashMap::new();
        for r in rows { let (k, v) = r?; m.insert(k, v); }
        Ok(m)
    }

    pub fn set_unread(&self, sid: &str, username: &str, count: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO unread(server_id,username,count) VALUES(?,?,?)
             ON CONFLICT(server_id,username) DO UPDATE SET count=excluded.count",
            params![sid, username, count])?;
        Ok(())
    }

    pub fn bump_unread(&self, sid: &str, username: &str, delta: i64) -> Result<()> {
        self.conn().execute(
            "INSERT INTO unread(server_id,username,count) VALUES(?,?,?)
             ON CONFLICT(server_id,username) DO UPDATE SET count=count+excluded.count",
            params![sid, username, delta])?;
        Ok(())
    }

    pub fn get_token(&self, sid: &str) -> Result<Option<String>> {
        let raw: Option<String> = self.conn().query_row(
            "SELECT value FROM meta WHERE server_id=? AND key='token'", params![sid], |r| r.get(0))
            .optional()?;
        Ok(raw.and_then(|s| serde_json::from_str::<String>(&s).ok()))
    }

    pub fn set_token(&self, sid: &str, token: &str) -> Result<()> {
        let enc = serde_json::to_string(token)?;
        self.conn().execute(
            "INSERT INTO meta(server_id,key,value) VALUES(?,'token',?)
             ON CONFLICT(server_id,key) DO UPDATE SET value=excluded.value",
            params![sid, enc])?;
        Ok(())
    }
}

/// Slice array elements byte-wise out of the **raw JSON text** (no deserialization), `array_key` e.g. `messages`. Offline messages
/// carry f64 `timestamp`s that `serde_json` re-formats (~12%), breaking verification; the minimal scan skips strings/escapes and splits top-level `{}`.
pub fn extract_json_array_objects(text: &str, array_key: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let needle = format!("\"{array_key}\"");
    let Some(key_pos) = text.find(&needle) else { return Vec::new() };
    let mut i = key_pos + needle.len();
    // skip the colon and whitespace, locate '['
    while i < bytes.len() && bytes[i] != b'[' {
        // bail at a same-level boundary so another structure is not matched
        if bytes[i] == b'}' || bytes[i] == b']' { return Vec::new(); }
        i += 1;
    }
    if i >= bytes.len() { return Vec::new(); }
    i += 1; // skip '['

    let mut out = Vec::new();
    let mut in_str = false;
    let mut escape = false;
    let mut depth = 0usize;
    let mut start: Option<usize> = None;

    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            if escape { escape = false; }
            else if c == b'\\' { escape = true; }
            else if c == b'"' { in_str = false; }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' => {
                if depth == 0 { start = Some(i); }
                depth += 1;
            }
            b'}' => {
                if depth > 0 {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = start.take() {
                            if let Ok(v) = std::str::from_utf8(&bytes[s..=i]) {
                                out.push(v.to_string());
                            }
                        }
                    }
                }
            }
            b']' if depth == 0 => break, // end of array
            _ => {}
        }
        i += 1;
    }
    out
}

/// Extract the raw `"timestamp"` number token from the **raw JSON text**, matching the key only outside string literals so a
/// `"timestamp"` in a body is not mistaken for it. Mandatory: parsing to f64 is lossy (~12%) while the signature covers the `fmt_ts` string, so a rebuilt digest fails at random and the message is dropped.
pub fn extract_timestamp_token(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    const KEY: &[u8] = b"\"timestamp\"";
    let mut i = 0usize;
    let mut in_str = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            match c {
                b'\\' => i += 1, // skip the escaped byte
                b'"' => in_str = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            // only at a structural position (not inside a string) can this be a key name
            if bytes[i..].starts_with(KEY) {
                let mut j = i + KEY.len();
                while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() { j += 1; }
                if j < bytes.len() && bytes[j] == b':' {
                    j += 1;
                    while j < bytes.len() && (bytes[j] as char).is_ascii_whitespace() { j += 1; }
                    let start = j;
                    while j < bytes.len() {
                        let d = bytes[j];
                        if d.is_ascii_digit() || matches!(d, b'-' | b'+' | b'.' | b'e' | b'E') {
                            j += 1;
                        } else {
                            break;
                        }
                    }
                    if j > start {
                        return std::str::from_utf8(&bytes[start..j]).ok().map(str::to_string);
                    }
                }
            }
            in_str = true;
            i += 1;
            continue;
        }
        i += 1;
    }
    None
}

    /// `chat_key = json.dumps(sorted([u1,u2]), ensure_ascii=False)`; ⚠️ Python's `json.dumps` default separator is ", " (comma+space), so it must match character for character.
pub fn make_chat_key(a: &str, b: &str) -> String {
    let (x, y) = if a <= b { (a, b) } else { (b, a) };
    format!("[\"{}\", \"{}\"]", json_escape(x), json_escape(y))
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Build a local time string, matching Python `datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")`.
pub fn fmt_db_time(ts: f64) -> String {
    use chrono::{Local, TimeZone};
    let secs = ts.trunc() as i64;
    let nanos = (ts.fract().abs() * 1e9) as u32;
    match Local.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => String::new(),
    }
}

/// Extract "HH:MM" from a stored "YYYY-MM-DD HH:MM:SS" for bubble headers.
pub fn hhmm(db_time: &str) -> String {
    if db_time.len() >= 16 { db_time[11..16].to_string() } else { db_time.to_string() }
}

#[cfg(test)]
mod local_status_tests {
    use super::*;

    fn mem() -> Store {
        Store::open(":memory:", None).expect("failed to open in-memory database")
    }

    #[test]
    fn find_and_update_message_by_msg_id_only() {
        let st = mem();
        let obj = serde_json::json!({"from": "me", "msg_id": "m1", "original": "hi"});
        assert!(st.insert_message("srv", "[\"a\", \"b\"]", Some("m1"), "me",
            &obj.to_string(), "2024-01-01 00:00:00", "hi").unwrap());

        // the ack carries only msg_id, not chat_key — lookup must still work
        let row = st.find_message_by_msg_id("srv", "m1").unwrap().expect("should locate the row by msg_id");
        assert_eq!(row.msg_id.as_deref(), Some("m1"));
        assert_eq!(row.sender, "me");

        st.update_message_content_by_sid_msg_id("srv", "m1",
            r#"{"from":"me","msg_id":"m1","local_status":"delivered"}"#).unwrap();
        let row = st.find_message_by_msg_id("srv", "m1").unwrap().unwrap();
        let v: Value = serde_json::from_str(&row.content).unwrap();
        assert_eq!(v.get(LOCAL_STATUS_KEY).and_then(|x| x.as_str()), Some("delivered"));

        // an unknown msg_id must not error
        assert!(st.find_message_by_msg_id("srv", "nope").unwrap().is_none());
    }

    #[test]
    fn set_local_status_writes_json_field() {
        let mut obj = serde_json::json!({"from": "me"});
        set_local_status(&mut obj, LOCAL_STATUS_FAILED);
        assert_eq!(obj.get(LOCAL_STATUS_KEY).and_then(|v| v.as_str()), Some("failed"));

        // a non-object must not panic
        let mut not_obj = serde_json::json!("plain");
        set_local_status(&mut not_obj, LOCAL_STATUS_SENT);
        assert_eq!(not_obj, serde_json::json!("plain"));
    }

    #[test]
    fn insert_server_clamps_port() {
        let st = mem();
        st.insert_server("s1", "n", "h", 99999).unwrap();
        let s = st.get_servers().unwrap().pop().unwrap();
        assert_eq!(s.api_port, PORT_MAX);

        st.insert_server("s2", "n", "h", 0).unwrap();
        let servers = st.get_servers().unwrap();
        assert_eq!(servers.iter().find(|s| s.id == "s2").unwrap().api_port, PORT_MIN);
    }
}

#[cfg(test)]
mod contact_nickname_tests {
    use super::*;

    fn mem() -> Store {
        Store::open(":memory:", None).unwrap()
    }

    /// Contact nickname round-trips; an empty string clears it (falls back to showing the user_id).
    #[test]
    fn set_and_clear_contact_nickname() {
        let st = mem();
        st.set_contact_public_key("srv", "118e00fa98", "PEM").unwrap();

        let c = st.get_contacts("srv").unwrap().pop().unwrap();
        assert_eq!(c.username, "118e00fa98");
        assert!(c.nickname.is_none(), "should have no nickname initially");
        // the public key must survive (renaming must not affect what signatures are checked against)
        assert_eq!(c.public_key.as_deref(), Some("PEM"));

        st.set_contact_nickname("srv", "118e00fa98", "Old Zhang").unwrap();
        let c = st.get_contacts("srv").unwrap().pop().unwrap();
        assert_eq!(c.nickname.as_deref(), Some("Old Zhang"));
        assert_eq!(c.public_key.as_deref(), Some("PEM"), "renaming must not clear the public key");

        st.set_contact_nickname("srv", "118e00fa98", "   ").unwrap();
        let c = st.get_contacts("srv").unwrap().pop().unwrap();
        assert!(c.nickname.is_none(), "a blank name must clear the nickname");

        st.set_contact_nickname("srv", "nobody", "x").unwrap();
    }

    /// A nickname equal to the user_id must stay distinct from "no nickname" (the rename dialog relies on this).
    #[test]
    fn nickname_equal_to_user_id_is_kept() {
        let st = mem();
        st.set_contact_public_key("srv", "a5112fd8ec", "PEM").unwrap();
        st.set_contact_nickname("srv", "a5112fd8ec", "a5112fd8ec").unwrap();
        let c = st.get_contacts("srv").unwrap().pop().unwrap();
        assert_eq!(c.nickname.as_deref(), Some("a5112fd8ec"));
    }
}

#[cfg(test)]
mod pending_state_tests {
    use super::*;

    fn mem() -> Store {
        Store::open(":memory:", None).unwrap()
    }

    fn file_msg(file_id: &str, with_original: bool) -> String {
        let mut obj = serde_json::json!({
            "from": "peer", "msg_type": "file", "msg_id": format!("m-{file_id}"),
            "file_id": file_id, "size": 100
        });
        if with_original {
            obj["original"] = serde_json::json!("/tmp/x");
        }
        obj.to_string()
    }

    #[test]
    fn json1_available() {
        let st = mem();
        let obj = serde_json::json!({"from":"me","msg_id":"j1"});
        st.insert_message("s","k",Some("j1"),"me",&obj.to_string(),"t","").unwrap();
        let n: i64 = st.conn().query_row(
            "SELECT count(*) FROM chat_messages WHERE json_extract(content,'$.from')='me'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "json_extract unavailable");
    }

    /// List only unfinished file messages, so downloads resume after a restart.
    #[test]
    fn lists_only_unfinished_file_downloads() {
        let st = mem();
        // unfinished (no original)
        st.insert_message("s","k",Some("m1"),"peer",&file_msg("f1", false),"t","").unwrap();
        st.insert_message("s","k",Some("m2"),"peer",&file_msg("f2", true),"t","").unwrap();
        st.insert_message("s","k",Some("m3"),"peer",
            &serde_json::json!({"from":"peer","msg_id":"m3","original":"hi"}).to_string(),"t","hi").unwrap();
        // another server — must not appear
        st.insert_message("other","k",Some("m4"),"peer",&file_msg("f4", false),"t","").unwrap();

        let rows = st.list_pending_file_downloads("s").unwrap();
        assert_eq!(rows.len(), 1, "should list exactly 1 unfinished file message");
        let v: Value = serde_json::from_str(&rows[0].content).unwrap();
        assert_eq!(v.get("file_id").and_then(|x| x.as_str()), Some("f1"));
    }

    /// On startup, collapse leftover sent into unknown without touching other states.
    #[test]
    fn downgrade_pending_sends_only_touches_sent() {
        let st = mem();
        for (mid, status) in [("a", LOCAL_STATUS_SENT), ("b", LOCAL_STATUS_DELIVERED),
                              ("c", LOCAL_STATUS_FAILED)] {
            let obj = serde_json::json!({"from":"me","msg_id":mid,"local_status":status});
            st.insert_message("s","k",Some(mid),"me",&obj.to_string(),"t","").unwrap();
        }
        let n = st.downgrade_pending_sends(LOCAL_STATUS_UNKNOWN).unwrap();
        assert_eq!(n, 1, "only the sent row should be rewritten");

        let get = |mid: &str| -> String {
            let row = st.find_message_by_msg_id("s", mid).unwrap().unwrap();
            let v: Value = serde_json::from_str(&row.content).unwrap();
            v.get(LOCAL_STATUS_KEY).and_then(|x| x.as_str()).unwrap_or("").to_string()
        };
        assert_eq!(get("a"), LOCAL_STATUS_UNKNOWN);
        assert_eq!(get("b"), LOCAL_STATUS_DELIVERED);
        assert_eq!(get("c"), LOCAL_STATUS_FAILED);
    }
}

#[cfg(test)]
mod s1_sqlcipher_tests {
    use super::*;

    /// With openmls linked, SQLCipher must still be real: a correct key reopens and reads back, a wrong key must fail (plain SQLite would "succeed").
    #[test]
    fn sqlcipher_roundtrip_and_wrong_key_fails() {
        let dir = std::env::temp_dir().join(format!("s1_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join("enc.db");
        let path = p.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }

        {
            let st = Store::open(&path, Some("KeyAAA")).expect("should create the DB with the correct key");
            st.insert_server("sid1", "name", "host", 1234).expect("insert failed");
        }
        {
            let st = Store::open(&path, Some("KeyAAA")).expect("should reopen with the correct key");
            let servers = st.get_servers().expect("read failed");
            assert_eq!(servers.len(), 1, "should read back 1 server");
            assert_eq!(servers[0].id, "sid1");
        }
        // wrong key must not open it (proves SQLCipher is linked)
        let wrong = Store::open(&path, Some("WrongKey"));
        assert!(wrong.is_err(),
            "the wrong key opened the database — this means SQLCipher is not linked in, and the 1v1 encrypted DB will be unreadable");
        assert!(Store::open(&path, None).and_then(|s| s.get_servers()).is_err(),
            "the encrypted DB was readable without providing a key");
    }
}

#[cfg(test)]
mod checkpoint_tests {
    use super::*;

    fn tmp_db(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "etemsg_ckpt_{}_{}.db",
            tag,
            std::process::id()
        ));
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{s}", p.display()));
        }
        p.to_string_lossy().to_string()
    }

    fn sizes(path: &str) -> (u64, u64) {
        let f = |s: &str| std::fs::metadata(format!("{path}{s}")).map(|m| m.len()).unwrap_or(0);
        (f(""), f("-wal"))
    }

    /// **Regression**: `checkpoint()` must fold `-wal` into the main DB. The process exits via `std::process::exit()` with threads
    /// still holding `Arc<Store>`, so SQLite's last-close checkpoint never fires and copying only `etemsg.db` would lose the data.
    #[test]
    fn checkpoint_folds_wal_into_main_db() {
        let path = tmp_db("fold");
        {
            let st = Store::open(&path, Some("k")).expect("open failed");
            // write enough data that the WAL is certainly non-empty
            st.insert_server("s1", "n", "h", 1).unwrap();
            for i in 0..200 {
                st.insert_group_message(
                    "s1", "g1", i, &format!("m{i}"), "u", &"x".repeat(200), 1, "ok",
                )
                .unwrap();
            }
            let (_db, wal_before) = sizes(&path);
            assert!(wal_before > 4096, "the WAL must be non-empty after writing, actual {wal_before}");

            st.checkpoint().expect("checkpoint failed");

            let (db_after, wal_after) = sizes(&path);
            assert!(
                db_after > 4096,
                "the main DB must contain data after checkpoint (no longer 1 page), actual {db_after}"
            );
            assert!(
                wal_after < wal_before,
                "the WAL must shrink after checkpoint: {wal_before} -> {wal_after}"
            );
            // the data must still be readable (checkpoint moves it, it does not delete it)
            assert_eq!(st.list_group_messages("s1", "g1", 0).unwrap().len(), 200);
        }
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{s}"));
        }
    }

    /// Calling checkpoint on an in-memory DB must not panic or error (pointless, but harmless).
    #[test]
    fn checkpoint_on_memory_db_is_harmless() {
        let st = Store::open(":memory:", None).unwrap();
        st.insert_server("s1", "n", "h", 1).unwrap();
        let _ = st.checkpoint();
    }
}
