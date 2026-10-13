//! Local persistence for group data (reusing the existing SQLCipher DB, separate tables).
//!
//! Constraints: fully separate from the 1v1 tables; `mls_private_state` (MLS state blob + signer blob) lands only in this encrypted DB and never in logs; group messages dedupe and resume by `(server_id, group_id, seq)`.

use anyhow::{Context, Result};
use rusqlite::params;

use super::state::{GroupRole, GroupState};
use crate::store::Store;

/// Local time string (same format as 1v1 message times, so the UI can show it directly).
pub fn local_now_string() -> String {
    crate::store::fmt_db_time(crate::crypto::chrono_now_ms() as f64 / 1000.0)
}

/// Group conversation row (local view).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub group_id: String,
    pub name_enc: Option<Vec<u8>>,
    pub my_role: GroupRole,
    pub current_epoch: u64,
    pub joined_epoch: u64,
    pub min_seq: u64,
}

impl GroupRow {
    pub fn to_state(&self, last_seq: u64) -> GroupState {
        GroupState {
            group_id: self.group_id.clone(),
            name_enc: self.name_enc.clone().unwrap_or_default(),
            my_role: self.my_role,
            current_epoch: self.current_epoch,
            joined_epoch: self.joined_epoch,
            min_seq: self.min_seq,
            last_seq,
        }
    }
}

/// Group member row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMemberRow {
    pub user_id: String,
    pub role: GroupRole,
    pub joined_epoch: u64,
    /// In-group nickname (from the MLS credential; empty means unset)
    pub nickname: String,
}

/// A persisted group message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMessageRow {
    pub seq: u64,
    pub msg_id: String,
    pub sender: String,
    pub plaintext: String,
    pub time: String,
    pub epoch: u64,
    /// `ok` = normal; `gap` = the message at this position was deleted server-side (a placeholder skipped over by the truncation watermark)
    pub state: String,
}

/// `state` values.
pub const MSG_OK: &str = "ok";
pub const MSG_GAP: &str = "gap";

impl Store {
    // Group conversations

    /// Insert or update the local group row (never touches `joined_epoch`, which is fixed at the first join).
    pub fn upsert_group(
        &self,
        server_id: &str,
        group_id: &str,
        name_enc: Option<&[u8]>,
        role: GroupRole,
        current_epoch: u64,
        joined_epoch: u64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO group_conversations
                (server_id, group_id, name_enc, my_role, current_epoch, joined_epoch, min_seq, joined_at)
             VALUES (?,?,?,?,?,?,0,?)
             ON CONFLICT(server_id, group_id) DO UPDATE SET
                name_enc = COALESCE(excluded.name_enc, group_conversations.name_enc),
                my_role = excluded.my_role,
                current_epoch = excluded.current_epoch",
            params![
                server_id,
                group_id,
                name_enc,
                role.as_str(),
                current_epoch as i64,
                joined_epoch as i64,
                crate::group::storage::local_now_string(),
            ],
        )?;
        Ok(())
    }

    pub fn get_group(&self, server_id: &str, group_id: &str) -> Result<Option<GroupRow>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT group_id, name_enc, my_role, current_epoch, joined_epoch, min_seq
             FROM group_conversations WHERE server_id=? AND group_id=?",
        )?;
        let mut rows = stmt.query(params![server_id, group_id])?;
        if let Some(r) = rows.next()? {
            let role: String = r.get(2)?;
            Ok(Some(GroupRow {
                group_id: r.get(0)?,
                name_enc: r.get(1)?,
                my_role: role.parse().unwrap_or(GroupRole::Member),
                current_epoch: r.get::<_, i64>(3)? as u64,
                joined_epoch: r.get::<_, i64>(4)? as u64,
                min_seq: r.get::<_, i64>(5)? as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// All groups I belong to, ordered by group_id so display stays stable.
    pub fn list_groups(&self, server_id: &str) -> Result<Vec<GroupRow>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT group_id, name_enc, my_role, current_epoch, joined_epoch, min_seq
             FROM group_conversations WHERE server_id=? ORDER BY group_id",
        )?;
        let mut out = Vec::new();
        let mut rows = stmt.query(params![server_id])?;
        while let Some(r) = rows.next()? {
            let role: String = r.get(2)?;
            out.push(GroupRow {
                group_id: r.get(0)?,
                name_enc: r.get(1)?,
                my_role: role.parse().unwrap_or(GroupRole::Member),
                current_epoch: r.get::<_, i64>(3)? as u64,
                joined_epoch: r.get::<_, i64>(4)? as u64,
                min_seq: r.get::<_, i64>(5)? as u64,
            });
        }
        Ok(out)
    }

    pub fn delete_group(&self, server_id: &str, group_id: &str) -> Result<()> {
        let c = self.conn();
        for t in [
            "group_conversations",
            "group_messages",
            "group_cursor",
            "group_unread",
            "mls_private_state",
            "mls_members",
        ] {
            c.execute(
                &format!("DELETE FROM {t} WHERE server_id=? AND group_id=?"),
                params![server_id, group_id],
            )?;
        }
        Ok(())
    }

    /// Update my role in this group (the server roster is authoritative; local is only a copy).
    pub fn set_group_role(&self, server_id: &str, group_id: &str, role: GroupRole) -> Result<()> {
        self.conn().execute(
            "UPDATE group_conversations SET my_role = ? WHERE server_id = ? AND group_id = ?",
            params![role.as_str(), server_id, group_id],
        )?;
        Ok(())
    }

    /// Update **one member's** role in this group (the server roster is authoritative).
    ///
    /// The local table is `mls_members` (`group_members` is the **server-side** name). MLS trees carry no roles, so other members' roles can only come from the server roster — without this, F9 showed stale roles after an owner transfer.
    pub fn set_member_role(
        &self,
        server_id: &str,
        group_id: &str,
        user_id: &str,
        role: GroupRole,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE mls_members SET role = ? WHERE server_id = ? AND group_id = ? AND user_id = ?",
            params![role.as_str(), server_id, group_id, user_id],
        )?;
        Ok(())
    }

    /// Replace the local member table wholesale with the ratchet tree's current member set: upserting alone would leave
    /// removed or departed members in the roster forever. Nicknames keep the "empty does not overwrite" guard (see `upsert_group_member`).
    pub fn replace_group_members(
        &self,
        server_id: &str,
        group_id: &str,
        members: &[(String, GroupRole, u64, String)],
    ) -> Result<()> {
        // One guard must be reused: `Store::conn()` is a non-reentrant MutexGuard, so calling `self.upsert_group_member`
        // (which takes the guard itself) would self-deadlock; the UPSERT is therefore inlined here.
        let c = self.conn();
        for (uid, role, epoch, nick) in members {
            c.execute(
                "INSERT INTO mls_members (server_id, group_id, user_id, role, joined_epoch, nickname)
                 VALUES (?,?,?,?,?,?)
                 ON CONFLICT(server_id, group_id, user_id) DO UPDATE SET
                    role=excluded.role, joined_epoch=excluded.joined_epoch,
                    nickname=CASE WHEN excluded.nickname <> '' THEN excluded.nickname
                                  ELSE mls_members.nickname END",
                params![server_id, group_id, uid, role.as_str(), *epoch as i64, nick],
            )?;
        }
        if members.is_empty() {
            c.execute(
                "DELETE FROM mls_members WHERE server_id = ? AND group_id = ?",
                params![server_id, group_id],
            )?;
            return Ok(());
        }
        let keep: Vec<String> = members.iter().map(|m| m.0.clone()).collect();
        let holders = vec!["?"; keep.len()].join(",");
        let sql = format!(
            "DELETE FROM mls_members
              WHERE server_id = ? AND group_id = ? AND user_id NOT IN ({holders})"
        );
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&server_id, &group_id];
        for k in &keep {
            args.push(k);
        }
        c.execute(&sql, args.as_slice())?;
        Ok(())
    }

    /// Update the locally stored group-name ciphertext (kept in sync after a rename).
    /// The authoritative name is the MLS group context; this column is only a copy of the server metadata plus a fallback for older groups.
    pub fn set_group_name_enc(
        &self,
        server_id: &str,
        group_id: &str,
        name_enc: &[u8],
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE group_conversations SET name_enc = ? WHERE server_id = ? AND group_id = ?",
            params![name_enc, server_id, group_id],
        )?;
        Ok(())
    }

    /// Advance the local epoch (called after receiving or merging a Commit).
    pub fn set_group_epoch(
        &self,
        server_id: &str,
        group_id: &str,
        epoch: u64,
    ) -> Result<()> {
        self.conn().execute(
            "UPDATE group_conversations SET current_epoch=? WHERE server_id=? AND group_id=?",
            params![epoch as i64, server_id, group_id],
        )?;
        Ok(())
    }

    // Group messages and cursors

    /// Persist one group message (same seq is ignored, so redelivery and refetch are safe); returns whether a row was actually inserted.
    pub fn insert_group_message(
        &self,
        server_id: &str,
        group_id: &str,
        seq: u64,
        msg_id: &str,
        sender: &str,
        plaintext: &str,
        epoch: u64,
        state: &str,
    ) -> Result<bool> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO group_messages
                (server_id, group_id, seq, msg_id, sender, plaintext, time, epoch, state)
             VALUES (?,?,?,?,?,?,?,?,?)",
            params![
                server_id,
                group_id,
                seq as i64,
                msg_id,
                sender,
                plaintext,
                crate::group::storage::local_now_string(),
                epoch as i64,
                state,
            ],
        )?;
        Ok(n > 0)
    }

    /// Read group messages in ascending seq order; `limit` 0 means unlimited.
    pub fn list_group_messages(
        &self,
        server_id: &str,
        group_id: &str,
        limit: usize,
    ) -> Result<Vec<GroupMessageRow>> {
        let c = self.conn();
        let sql = if limit == 0 {
            "SELECT seq, msg_id, sender, plaintext, time, epoch, state
             FROM group_messages WHERE server_id=? AND group_id=? ORDER BY seq"
                .to_string()
        } else {
            format!(
                "SELECT seq, msg_id, sender, plaintext, time, epoch, state
                 FROM group_messages WHERE server_id=? AND group_id=? ORDER BY seq LIMIT {limit}"
            )
        };
        let mut stmt = c.prepare(&sql)?;
        let mut out = Vec::new();
        let mut rows = stmt.query(params![server_id, group_id])?;
        while let Some(r) = rows.next()? {
            out.push(GroupMessageRow {
                seq: r.get::<_, i64>(0)? as u64,
                msg_id: r.get(1)?,
                sender: r.get(2)?,
                plaintext: r.get(3)?,
                time: r.get(4)?,
                epoch: r.get::<_, i64>(5)? as u64,
                state: r.get(6)?,
            });
        }
        Ok(out)
    }

    /// The acked position.
    pub fn group_last_seq(&self, server_id: &str, group_id: &str) -> Result<u64> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT last_seq FROM group_cursor WHERE server_id=? AND group_id=?",
        )?;
        let mut rows = stmt.query(params![server_id, group_id])?;
        Ok(match rows.next()? {
            Some(r) => r.get::<_, i64>(0)? as u64,
            None => 0,
        })
    }

    /// Advance the ack cursor (**monotonic**: a lower value is ignored).
    pub fn set_group_last_seq(
        &self,
        server_id: &str,
        group_id: &str,
        last_seq: u64,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO group_cursor (server_id, group_id, last_seq, min_seq)
             VALUES (?,?,?,0)
             ON CONFLICT(server_id, group_id) DO UPDATE SET
                last_seq = MAX(group_cursor.last_seq, excluded.last_seq)",
            params![server_id, group_id, last_seq as i64],
        )?;
        Ok(())
    }

    /// Record the server's deletion lower bound (`min_seq`).
    pub fn set_group_min_seq(
        &self,
        server_id: &str,
        group_id: &str,
        min_seq: u64,
    ) -> Result<()> {
        // `Store::conn()` is a non-reentrant Mutex; taking it twice in one function self-deadlocks, so the calls below share one guard.
        let c = self.conn();
        c.execute(
            "INSERT INTO group_cursor (server_id, group_id, last_seq, min_seq)
             VALUES (?,?,0,?)
             ON CONFLICT(server_id, group_id) DO UPDATE SET
                min_seq = MAX(group_cursor.min_seq, excluded.min_seq)",
            params![server_id, group_id, min_seq as i64],
        )?;
        // The conversation table's min_seq is **increase-only** too: a plain SET could be overwritten by a smaller value
        c.execute(
            "UPDATE group_conversations SET min_seq=MAX(min_seq, ?)
             WHERE server_id=? AND group_id=?",
            params![min_seq as i64, server_id, group_id],
        )?;
        Ok(())
    }

    // MLS private state (most sensitive)

    /// Persist the MLS state blob and the signer blob.
    /// Callers must never print these two blobs to logs — together they are the group's identity private key.
    pub fn save_mls_state(
        &self,
        server_id: &str,
        group_id: &str,
        epoch: u64,
        state_blob: &[u8],
        signer_blob: &[u8],
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mls_private_state
                (server_id, group_id, epoch, state_blob, signer_blob, updated_at)
             VALUES (?,?,?,?,?,?)
             ON CONFLICT(server_id, group_id) DO UPDATE SET
                epoch=excluded.epoch,
                state_blob=excluded.state_blob,
                signer_blob=excluded.signer_blob,
                updated_at=excluded.updated_at",
            params![
                server_id,
                group_id,
                epoch as i64,
                state_blob,
                signer_blob,
                crate::group::storage::local_now_string(),
            ],
        )?;
        Ok(())
    }

    /// Read the MLS state blob and the signer blob.
    pub fn load_mls_state(
        &self,
        server_id: &str,
        group_id: &str,
    ) -> Result<Option<(u64, Vec<u8>, Vec<u8>)>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT epoch, state_blob, signer_blob FROM mls_private_state
             WHERE server_id=? AND group_id=?",
        )?;
        let mut rows = stmt.query(params![server_id, group_id])?;
        match rows.next()? {
            Some(r) => Ok(Some((
                r.get::<_, i64>(0)? as u64,
                r.get(1)?,
                r.get(2)?,
            ))),
            None => Ok(None),
        }
    }

    // Members and unread counters

    pub fn upsert_group_member(
        &self,
        server_id: &str,
        group_id: &str,
        user_id: &str,
        role: GroupRole,
        joined_epoch: u64,
        nickname: &str,
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO mls_members (server_id, group_id, user_id, role, joined_epoch, nickname)
             VALUES (?,?,?,?,?,?)
             ON CONFLICT(server_id, group_id, user_id) DO UPDATE SET
                role=excluded.role, joined_epoch=excluded.joined_epoch,
                -- Only overwrite the nickname when a new value is present, so an empty value cannot wipe a known one
                nickname=CASE WHEN excluded.nickname <> '' THEN excluded.nickname
                              ELSE mls_members.nickname END",
            params![
                server_id, group_id, user_id, role.as_str(), joined_epoch as i64, nickname
            ],
        )?;
        Ok(())
    }

    pub fn remove_group_member(
        &self,
        server_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<()> {
        self.conn().execute(
            "DELETE FROM mls_members WHERE server_id=? AND group_id=? AND user_id=?",
            params![server_id, group_id, user_id],
        )?;
        Ok(())
    }

    /// Group member list (with roles and nicknames), ordered by user_id.
    pub fn list_group_members(
        &self,
        server_id: &str,
        group_id: &str,
    ) -> Result<Vec<GroupMemberRow>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT user_id, role, joined_epoch, nickname FROM mls_members
             WHERE server_id=? AND group_id=? ORDER BY user_id",
        )?;
        let mut out = Vec::new();
        let mut rows = stmt.query(params![server_id, group_id])?;
        while let Some(r) = rows.next()? {
            let role: String = r.get(1)?;
            out.push(GroupMemberRow {
                user_id: r.get(0)?,
                role: role.parse().unwrap_or(GroupRole::Member),
                joined_epoch: r.get::<_, i64>(2)? as u64,
                nickname: r.get(3)?,
            });
        }
        Ok(out)
    }

    /// One member's in-group nickname (used for the message-bubble sender label).
    pub fn group_member_nickname(
        &self,
        server_id: &str,
        group_id: &str,
        user_id: &str,
    ) -> Result<Option<String>> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT nickname FROM mls_members
             WHERE server_id=? AND group_id=? AND user_id=?",
        )?;
        let mut rows = stmt.query(params![server_id, group_id, user_id])?;
        Ok(match rows.next()? {
            Some(r) => {
                let n: String = r.get(0)?;
                if n.is_empty() { None } else { Some(n) }
            }
            None => None,
        })
    }

    pub fn bump_group_unread(
        &self,
        server_id: &str,
        group_id: &str,
        by: i64,
    ) -> Result<i64> {
        // Shares one guard as above. Negative (or zero) increments are ignored: writing `MAX(0, count + by)` would zero the counter when by is negative.
        let c = self.conn();
        let by = by.max(0);
        if by > 0 {
            // Placeholder and parameter counts must match (a past bug wrote `VALUES (?,?,0)` while passing 3 params, silently dropping the increment).
            c.execute(
                "INSERT INTO group_unread (server_id, group_id, count) VALUES (?,?,?)
                 ON CONFLICT(server_id, group_id) DO UPDATE SET
                    count = group_unread.count + excluded.count",
                params![server_id, group_id, by],
            )?;
        }
        let n: i64 = c.query_row(
            "SELECT count FROM group_unread WHERE server_id=? AND group_id=?",
            params![server_id, group_id],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    pub fn clear_group_unread(&self, server_id: &str, group_id: &str) -> Result<()> {
        self.conn().execute(
            "INSERT INTO group_unread (server_id, group_id, count) VALUES (?,?,0)
             ON CONFLICT(server_id, group_id) DO UPDATE SET count=0",
            params![server_id, group_id],
        )?;
        Ok(())
    }

    pub fn group_unread(&self, server_id: &str, group_id: &str) -> Result<i64> {
        let c = self.conn();
        let mut stmt = c.prepare(
            "SELECT count FROM group_unread WHERE server_id=? AND group_id=?",
        )?;
        let mut rows = stmt.query(params![server_id, group_id])?;
        Ok(match rows.next()? {
            Some(r) => r.get(0)?,
            None => 0,
        })
    }

    /// Open an existing group (reads back business state + MLS state).
    pub fn open_group_ctx(
        &self,
        server_id: &str,
        group_id: &str,
    ) -> Result<Option<GroupCtx>> {
        let Some(row) = self.get_group(server_id, group_id)? else {
            return Ok(None);
        };
        let Some((epoch, state_blob, signer_blob)) =
            self.load_mls_state(server_id, group_id)?
        else {
            return Ok(None);
        };
        let last_seq = self.group_last_seq(server_id, group_id)?;
        Ok(Some(GroupCtx {
            state: row.to_state(last_seq),
            mls_epoch: epoch,
            state_blob,
            signer_blob,
        }))
    }
}

/// Everything local needed to open a group.
#[derive(Debug, Clone)]
pub struct GroupCtx {
    pub state: GroupState,
    /// Epoch recorded in the MLS state blob (should match `state.current_epoch`)
    pub mls_epoch: u64,
    pub state_blob: Vec<u8>,
    pub signer_blob: Vec<u8>,
}

impl GroupCtx {
    /// Persist the current MLS state (called after every epoch change or send/receive).
    pub fn persist(&self, store: &Store, server_id: &str, epoch: u64) -> Result<()> {
        store
            .save_mls_state(
                server_id,
                &self.state.group_id,
                epoch,
                &self.state_blob,
                &self.signer_blob,
            )
            .with_context(|| format!("failed to save MLS state group={}", self.state.group_id))
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    use crate::store::Store;

    fn mem() -> Store {
        Store::open(":memory:", None).expect("failed to open the in-memory database")
    }

    /// Guards schema completeness: a fresh DB carries every group table (including the `nickname` column); there is no migration or backward compatibility.
    #[test]
    fn fresh_database_has_complete_group_schema() {
        let path = std::env::temp_dir().join(format!("fresh_{}.db", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{s}"));
        }

        let st = Store::open(&path, None).expect("failed to create the database");
        for t in [
            "group_conversations",
            "group_messages",
            "group_cursor",
            "group_unread",
            "mls_private_state",
            "mls_members",
        ] {
            let n: i64 = st
                .conn()
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
                    [t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "a fresh database should already contain table {t}");
        }
        let has_nick: i64 = st
            .conn()
            .query_row(
                "SELECT count(*) FROM pragma_table_info('mls_members') WHERE name='nickname'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_nick, 1, "mls_members.nickname should be created together with the schema");

        st.upsert_group("srv", "g1", None, GroupRole::Owner, 0, 0).unwrap();
        st.upsert_group_member("srv", "g1", "u1", GroupRole::Owner, 0, "nickname").unwrap();
        assert_eq!(
            st.group_member_nickname("srv", "g1", "u1").unwrap().as_deref(),
            Some("nickname")
        );

        for s in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{s}"));
        }
    }

    /// Guards group CRUD, cursor monotonicity, and message dedup.
    #[test]
    fn group_conversation_and_cursor_roundtrip() {
        let st = mem();
        st.upsert_group("srv", "g1", Some(b"enc-name"), GroupRole::Owner, 0, 0)
            .unwrap();
        let g = st.get_group("srv", "g1").unwrap().expect("should read back");
        assert_eq!(g.my_role, GroupRole::Owner);
        assert_eq!(g.name_enc.as_deref(), Some(&b"enc-name"[..]));
        assert_eq!(st.list_groups("srv").unwrap().len(), 1);

        st.set_group_epoch("srv", "g1", 3).unwrap();
        assert_eq!(st.get_group("srv", "g1").unwrap().unwrap().current_epoch, 3);

        st.set_group_last_seq("srv", "g1", 5).unwrap();
        assert_eq!(st.group_last_seq("srv", "g1").unwrap(), 5);
        st.set_group_last_seq("srv", "g1", 2).unwrap();
        assert_eq!(st.group_last_seq("srv", "g1").unwrap(), 5, "the cursor must not go backwards");

        st.set_group_min_seq("srv", "g1", 4).unwrap();
        st.set_group_min_seq("srv", "g1", 1).unwrap();
        assert_eq!(st.get_group("srv", "g1").unwrap().unwrap().min_seq, 4);

        assert!(st
            .insert_group_message("srv", "g1", 1, "m1", "alice", "hi", 1, MSG_OK)
            .unwrap());
        assert!(
            !st.insert_group_message("srv", "g1", 1, "m1", "alice", "hi", 1, MSG_OK)
                .unwrap(),
            "a duplicate insert with the same seq should be ignored"
        );
        let msgs = st.list_group_messages("srv", "g1", 0).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].plaintext, "hi");
    }

    /// Guards the MLS private-state round-trip (most sensitive material).
    #[test]
    fn mls_private_state_roundtrip() {
        let st = mem();
        assert!(st.load_mls_state("srv", "g1").unwrap().is_none());
        st.save_mls_state("srv", "g1", 2, b"STATE", b"KEY").unwrap();
        let (ep, state, key) = st.load_mls_state("srv", "g1").unwrap().unwrap();
        assert_eq!((ep, state.as_slice(), key.as_slice()), (2, &b"STATE"[..], &b"KEY"[..]));
        st.save_mls_state("srv", "g1", 3, b"STATE2", b"KEY2").unwrap();
        let (ep, state, _) = st.load_mls_state("srv", "g1").unwrap().unwrap();
        assert_eq!((ep, state.as_slice()), (3, &b"STATE2"[..]));
    }

    /// Guards that deleting a group clears all of its local rows without touching other groups.
    #[test]
    fn delete_group_clears_only_that_group() {
        let st = mem();
        for g in ["g1", "g2"] {
            st.upsert_group("srv", g, None, GroupRole::Member, 1, 1).unwrap();
            st.save_mls_state("srv", g, 1, b"S", b"K").unwrap();
            st.insert_group_message("srv", g, 1, "m", "u", "x", 1, MSG_OK).unwrap();
        }
        st.delete_group("srv", "g1").unwrap();
        assert!(st.get_group("srv", "g1").unwrap().is_none());
        assert!(st.load_mls_state("srv", "g1").unwrap().is_none());
        assert!(st.list_group_messages("srv", "g1", 0).unwrap().is_empty());
        assert!(st.get_group("srv", "g2").unwrap().is_some());
        assert_eq!(st.list_group_messages("srv", "g2", 0).unwrap().len(), 1);
    }

    /// Guards unread counters and the member table.
    #[test]
    fn unread_and_members() {
        let st = mem();
        st.bump_group_unread("srv", "g1", 3).unwrap();
        assert_eq!(st.group_unread("srv", "g1").unwrap(), 3);
        st.bump_group_unread("srv", "g1", -5).unwrap(); // a negative delta does not decrease the count
        assert_eq!(st.group_unread("srv", "g1").unwrap(), 3);
        st.clear_group_unread("srv", "g1").unwrap();
        assert_eq!(st.group_unread("srv", "g1").unwrap(), 0);

        st.upsert_group_member("srv", "g1", "alice", GroupRole::Owner, 0, "Alice")
            .unwrap();
        st.upsert_group_member("srv", "g1", "bob", GroupRole::Member, 1, "Bob")
            .unwrap();
        let ms = st.list_group_members("srv", "g1").unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].user_id, "alice");
        assert!(ms[0].role.can_commit());
        assert_eq!(ms[0].nickname, "Alice");
        assert_eq!(ms[1].nickname, "Bob");

        assert_eq!(
            st.group_member_nickname("srv", "g1", "bob").unwrap().as_deref(),
            Some("Bob")
        );
        assert!(st.group_member_nickname("srv", "g1", "nobody").unwrap().is_none());

        st.upsert_group_member("srv", "g1", "bob", GroupRole::Member, 1, "").unwrap();
        assert_eq!(ms[1].nickname, "Bob", "an empty nickname should not overwrite an existing nickname");
        assert_eq!(
            st.group_member_nickname("srv", "g1", "bob").unwrap().as_deref(),
            Some("Bob")
        );

        st.remove_group_member("srv", "g1", "bob").unwrap();
        assert_eq!(st.list_group_members("srv", "g1").unwrap().len(), 1);
    }
}
