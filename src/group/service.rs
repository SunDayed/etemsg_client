//! Group flow orchestration: stitches MLS (`adapter`) to the protocol (`transport`).
//!
//! Covers creation, join request/approval, sending and receiving, and epoch rotation; `mls_private_state` (MLS state blob + signer blob) goes only into SQLCipher and never into logs or error messages.

use std::sync::Arc;

use anyhow::{bail, Context, Result};

use super::adapter::{self, MlsAdapter, Opened, RestoreInput};
use super::state::{GroupRole, GroupState};
use super::storage::{MSG_OK, GroupMessageRow};
use super::transport::{
    CreateGroupReq, GroupDetail, GroupMsgRecord, GroupSearchHit, GroupTransport, JoinRequestRecord,
    MemberInfo,
};
use crate::crypto;
use crate::store::Store;

/// Decrypt a group name without network or login, for UI rendering (a name may be shown every frame, and that must not open a TLS connection).
/// Unlike [`GroupService::decrypt_group_name`] it reads only the local SQLCipher DB and MLS state.
pub fn decrypt_group_name_local(
    store: &Store,
    sid: &str,
    group_id: &str,
) -> Result<Option<String>> {
    let Some(row) = store.get_group(sid, group_id)? else {
        return Ok(None);
    };
    let Some((_, state_blob, signer_blob)) = store.load_mls_state(sid, group_id)? else {
        return Ok(None);
    };
    let adapter = MlsAdapter::restore(RestoreInput {
        signer_blob: &signer_blob,
        state_blob: &state_blob,
        group_id: group_id.as_bytes(),
    })
    .map_err(|e| anyhow::anyhow!("failed to restore group state: {e}"))?;

    // Preferred: the name lives in the group context (a rename updates it along with the Commit)
    if let Some(payload) = adapter.name_ext() {
        if let Some((key, Some(name))) = parse_name_ext(&payload) {
            let _ = key;
            return Ok(Some(name));
        }
    }

    // Fallback: early groups carry only the key in the group context, the ciphertext sits in the local name_enc column
    let Some(name_enc) = row.name_enc else { return Ok(None) };
    if name_enc.is_empty() {
        return Ok(None);
    }
    let Some(key) = adapter.name_key() else {
        return Ok(None);
    };
    let plain = open_blob(&key, &name_enc)?;
    Ok(Some(String::from_utf8(plain).context("group name is not valid UTF-8")?))
}

/// Separator between `user_id` and the in-group nickname inside the MLS credential (U+001F: user_id is lowercase hex, so it never occurs in a nickname).
/// The nickname must be visible to other members yet not stored by the server (an opaque forwarder); the credential travels with KeyPackage/Welcome/Commit and is authenticated by MLS signatures.
pub const CRED_SEP: char = '\u{1f}';

/// Encode `user_id` and a nickname into an MLS credential identity.
pub fn encode_credential(user_id: &str, nickname: &str) -> String {
    let nick: String = nickname.chars().filter(|c| *c != CRED_SEP).collect();
    if nick.is_empty() {
        user_id.to_string()
    } else {
        format!("{user_id}{CRED_SEP}{nick}")
    }
}

/// Decode a credential identity into `(user_id, nickname)`.
pub fn decode_credential(identity: &str) -> (String, String) {
    match identity.split_once(CRED_SEP) {
        Some((uid, nick)) => (uid.to_string(), nick.to_string()),
        None => (identity.to_string(), String::new()),
    }
}

/// Group ID length: 10 chars of lowercase base36 (digits + lowercase letters).
/// 36^10 is about 3.7e15, so collisions are vanishingly rare and the server's unique constraint backstops it; 10 chars keeps the ID readable and hand-copyable.
pub const GROUP_ID_LEN: usize = 10;

/// base36 alphabet: 0-9 and a-z (lowercase only, to avoid case confusion).
const BASE36: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Generate a new group ID (10 chars of lowercase base36).
pub fn new_group_id() -> String {
    use rand::RngCore;
    let mut out = String::with_capacity(GROUP_ID_LEN);
    let mut buf = [0u8; GROUP_ID_LEN];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    for b in buf {
        // 252 = 36*7: 256 % 36 != 0 would bias the modulo, so bytes falling in the biased range are redrawn (rejection sampling).
        let mut v = b as usize;
        while v >= 252 {
            let mut one = [0u8; 1];
            rand::rngs::OsRng.fill_bytes(&mut one);
            v = one[0] as usize;
        }
        out.push(BASE36[v % 36] as char);
    }
    out
}

/// Whether a group ID is valid: exactly [`GROUP_ID_LEN`] chars of `[0-9a-z]`.
pub fn is_valid_group_id(s: &str) -> bool {
    s.len() == GROUP_ID_LEN
        && s.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
}

/// Group service: the entry point for all group operations.
pub struct GroupService {
    store: Arc<Store>,
    transport: Arc<dyn GroupTransport + Send + Sync>,
    /// Current server id (group data is isolated per server)
    server_id: String,
    /// Local user_id (also the in-group credential identity)
    username: String,
    /// RSA private key (for signed REST and join-note encryption), from the 1v1 identity
    priv_key: std::sync::Arc<rsa::RsaPrivateKey>,
}

/// Local context of one pending join (request submitted, waiting for approval).
/// Must be persisted: the KeyPackage's private material sits in provider storage, and losing it means the Welcome can never be consumed.
#[derive(Debug, Clone)]
pub struct PendingJoin {
    pub group_id: String,
    pub request_id: String,
    pub kp_id: String,
}

impl GroupService {
    pub fn new(
        store: Arc<Store>,
        transport: Arc<dyn GroupTransport + Send + Sync>,
        server_id: impl Into<String>,
        username: impl Into<String>,
        priv_key: std::sync::Arc<rsa::RsaPrivateKey>,
    ) -> Self {
        Self {
            store,
            transport,
            server_id: server_id.into(),
            username: username.into(),
            priv_key,
        }
    }

    fn sid(&self) -> &str {
        &self.server_id
    }

    /// Local user_id (also the identity prefix in the group credential).
    pub fn username(&self) -> &str {
        &self.username
    }

    // Creating a group

    /// Create a group and return the locally persisted state.
    /// Pipeline: group ID -> MLS group at epoch 0 -> name encrypted with the group key -> notify server -> persist. `my_nickname` is required (it goes into the MLS credential other members see).
    pub fn create_group(&self, group_name: &str, my_nickname: &str) -> Result<GroupState> {
        let group_name = group_name.trim();
        let my_nickname = my_nickname.trim();
        if group_name.is_empty() {
            bail!("group name must not be empty");
        }
        if my_nickname.is_empty() {
            bail!("in-group nickname must not be empty");
        }
        // base36 can collide and the server primary key rejects duplicates; 5 retries is plenty.
        let mut attempt = 0;
        let (group_id, name_enc, adapter) = loop {
            attempt += 1;
            let group_id = new_group_id();
            if !is_valid_group_id(&group_id) {
                bail!("generated group ID is invalid: {group_id}");
            }

            let (provider, signer, signer_blob, _pub) =
                adapter::new_identity().map_err(|e| anyhow::anyhow!("failed to generate the group identity: {e}"))?;
            let cred = encode_credential(&self.username, my_nickname);
            // Name (key + ciphertext) goes into the group context: the key is constant across epochs and the ciphertext lets new members read the name straight from the Welcome.
            let name_key = adapter::random_name_key();
            let name_ext = build_name_ext(&name_key, group_name)?;
            let adapter = MlsAdapter::create_group_with_name_key(
                provider,
                signer,
                cred.as_bytes(),
                group_id.as_bytes(),
                &name_ext,
            )
            .map_err(|e| anyhow::anyhow!("group creation failed: {e}"))?;

            // The server keeps one ciphertext copy (unreadable to it) as metadata for group lists and search.
            let name_enc = seal_blob(&name_key, group_name.as_bytes())?;

            match self.transport.create_group(&CreateGroupReq {
                group_id: group_id.clone(),
                name_enc: name_enc.clone(),
            }) {
                Ok(_) => break (group_id, name_enc, (adapter, signer_blob)),
                // Only "group ID already exists" is worth retrying with a fresh ID
                Err(e)
                    if attempt < 5
                        && (format!("{e:#}").contains("GROUP_EXISTS")
                            || format!("{e:#}").contains("DUPLICATE")) =>
                {
                    continue;
                }
                Err(e) => return Err(e).context("the server rejected group creation"),
            }
        };
        let (adapter, signer_blob) = adapter;

        let epoch = adapter.epoch();
        self.store.upsert_group(
            self.sid(),
            &group_id,
            Some(&name_enc),
            GroupRole::Owner,
            epoch,
            0,
        )?;
        self.store.upsert_group_member(
            self.sid(),
            &group_id,
            &self.username,
            GroupRole::Owner,
            0,
            my_nickname,
        )?;
        let state_blob = adapter
            .export_state()
            .map_err(|e| anyhow::anyhow!("failed to export MLS state: {e}"))?;
        self.store
            .save_mls_state(self.sid(), &group_id, epoch, &state_blob, &signer_blob)?;

        self.load_state(&group_id)?
            .context("the group should be readable locally after creation")
    }

    // Requesting to join

    /// Search by group ID (by design, searching by name is not supported).
    pub fn search_group(&self, group_id: &str) -> Result<Vec<GroupSearchHit>> {
        self.transport.search_by_id(group_id)
    }

    /// Submit a join request; `my_nickname` and `text` are both required.
    /// The nickname must be fixed before the KeyPackage is built (it goes into the credential, is submitted with the request, and enters the group with the Add).
    /// Build the identity and the KeyPackage on that provider first, then persist provider state together with the signer, or the join cannot complete after approval.
    pub fn request_join(&self, group_id: &str, text: &str, my_nickname: &str) -> Result<PendingJoin> {
        let my_nickname = my_nickname.trim();
        let text = text.trim();
        if my_nickname.is_empty() {
            bail!("in-group nickname must not be empty");
        }
        if text.is_empty() {
            bail!("the join request note must not be empty");
        }
        // Validate the ID format locally first: the owner copies it out by hand, so this is clearer than the server's INVALID_GROUP_ID.
        if !is_valid_group_id(group_id) {
            bail!(
                "invalid group ID format: expected {GROUP_ID_LEN} digits or lowercase letters, but got {group_id}"
            );
        }
        let hits = self.search_group(group_id)?;
        let hit = hits
            .iter()
            .find(|h| h.group_id == group_id)
            .context("group not found")?;

        // The note is encrypted to the approver (the current owner, not the creator): after a transfer the two differ, and encrypting to the creator would leave the new owner seeing "cannot decrypt".
        // Whichever key is used, `public_key_id(pub) == the matching user_id` must be verified locally first, so the server cannot substitute a key.
        let (approver, approver_key) = if !hit.owner.is_empty() && !hit.owner_public_key.is_empty() {
            (hit.owner.as_str(), hit.owner_public_key.as_str())
        } else {
            // The server reported no owner (old server, or the group has none right now) -> fall back to the creator
            (hit.creator.as_str(), hit.creator_public_key.as_str())
        };
        let derived = crypto::public_key_id(approver_key, 10)?;
        if derived != approver {
            bail!(
                "approver public key does not match its user_id (expected {}, got {}) -- refusing to use this group's public key",
                approver,
                derived
            );
        }

        // Generate the group identity + KeyPackage
        let (provider, signer, signer_blob, _pub) =
            adapter::new_identity().map_err(|e| anyhow::anyhow!("failed to generate the group identity: {e}"))?;
        let cred = encode_credential(&self.username, my_nickname);
        let kp_bytes = adapter::make_key_package_with(&provider, &signer, cred.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to generate the KeyPackage: {e}"))?;
        let kp_b64 = base64_encode(&kp_bytes);
        let kp_hash = crypto::sha256_hex(&kp_bytes);
        let kp_id = crypto::generate_msg_id();

        // Persist provider state (holding KeyPackage private material) first, for the join after approval
        let provider_blob = adapter::export_provider_state(&provider)
            .map_err(|e| anyhow::anyhow!("failed to export provider state: {e}"))?;
        self.store
            .save_mls_state(self.sid(), group_id, 0, &provider_blob, &signer_blob)?;

        // Upload the KeyPackage + submit the request
        self.transport
            .upload_key_package(group_id, &kp_id, &kp_b64, &kp_hash)
            .context("failed to upload the KeyPackage")?;

        // The note is encrypted to the **current owner**'s public key (only they can decrypt it)
        let (ct, iv, tag, wrapped) = crypto::encrypt_text(text, approver_key)?;
        let request_id = crypto::generate_msg_id();
        self.transport
            .submit_join_request(&JoinRequestRecord {
                request_id: request_id.clone(),
                group_id: group_id.to_string(),
                applicant: self.username.clone(),
                kp_id: kp_id.clone(),
                kp_hash,
                text_ct: ct,
                text_iv: iv,
                text_tag: tag,
                text_wrapped_key: wrapped,
                status: "pending".into(),
            })
            .context("failed to submit the join request")?;

        // Record a local placeholder group row (pending, not yet joined)
        self.store.upsert_group(
            self.sid(),
            group_id,
            hit.name_enc.as_deref(),
            GroupRole::Member,
            0,
            0,
        )?;

        Ok(PendingJoin { group_id: group_id.to_string(), request_id, kp_id })
    }

    /// Consume my own Welcome to complete the join (called after approval); returns the epoch after joining.
    pub fn complete_join(&self, group_id: &str) -> Result<u64> {
        let (_, provider_blob, signer_blob) = self
            .store
            .load_mls_state(self.sid(), group_id)?
            .context("missing the MLS state saved during the request phase (the KeyPackage private key is lost)")?;

        let welcomes = self.transport.list_welcomes(group_id)?;
        let w = welcomes
            .iter()
            .find(|w| w.target == self.username)
            .context("the server has not provided a Welcome for me yet")?;
        let welcome_bytes = base64_decode(&w.data_b64)?;

        let provider = adapter::import_provider_state(&provider_blob)
            .map_err(|e| anyhow::anyhow!("failed to restore provider state: {e}"))?;
        let signer = adapter::signer_from_blob(&signer_blob)
            .map_err(|e| anyhow::anyhow!("failed to restore the signer: {e}"))?;

        // The owner attaches the ratchet tree via Commit (fetched from the server log here; the caller retries if it is missing)
        let ratchet_tree = self.try_fetch_ratchet_tree(group_id, w.epoch)?;

        let adapter =
            MlsAdapter::join_from_welcome(provider, signer, &welcome_bytes, ratchet_tree)
                .map_err(|e| anyhow::anyhow!("joining the group failed: {e}"))?;
        let epoch = adapter.epoch();

        // After joining: joined_epoch = current epoch (messages from before the join stay invisible)
        self.store
            .upsert_group(self.sid(), group_id, None, GroupRole::Member, epoch, epoch)?;
        // The local member table follows the **MLS ratchet tree** (the server's table is not trusted)
        self.sync_members_from_mls(group_id, &adapter, epoch)?;
        let state_blob = adapter
            .export_state()
            .map_err(|e| anyhow::anyhow!("failed to export group state: {e}"))?;
        self.store
            .save_mls_state(self.sid(), group_id, epoch, &state_blob, &signer_blob)?;
        Ok(epoch)
    }

    /// Look for a message carrying a ratchet tree in the control log; None if there is none (openmls then falls back to the tree embedded in the Welcome).
    fn try_fetch_ratchet_tree(&self, _group_id: &str, _epoch: u64) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    // Approval

    /// Owner/admin: fetch pending requests and decrypt their notes locally, returning `(request, plaintext)`.
    /// A decryption failure does not abort the list. A former owner keeps approval rights over requests that predate the transfer, but `decide` checks membership first, so that rule is unreachable once they leave.
    pub fn list_join_requests(&self, group_id: &str) -> Result<Vec<(JoinRequestRecord, String)>> {
        let rows = self.transport.list_join_requests(group_id)?;
        let out = rows
            .into_iter()
            .map(|r| {
                let text = self.decrypt_join_text(&r).unwrap_or_else(|e| {
                    format!("<undecryptable: {e}>")
                });
                (r, text)
            })
            .collect();
        Ok(out)
    }

    /// The in-group nickname the applicant claims (read from their KeyPackage credential).
    /// The applicant is not a member yet, so the nickname is not in the member table; any failure returns None and never blocks approval.
    pub fn applicant_nickname(&self, group_id: &str, kp_id: &str) -> Option<String> {
        let kp_b64 = match self.transport.fetch_key_package(group_id, kp_id) {
            Ok(v) => v,
            Err(e) => {
                crate::tui_log!("reading the applicant nickname: fetching the KeyPackage failed kp={kp_id}: {e:#}");
                return None;
            }
        };
        let kp_bytes = match base64_decode(&kp_b64) {
            Ok(v) => v,
            Err(e) => {
                crate::tui_log!("reading the applicant nickname: base64 decode failed: {e:#}");
                return None;
            }
        };
        let identity = match adapter::key_package_identity(&kp_bytes) {
            Some(v) => v,
            None => {
                crate::tui_log!("reading the applicant nickname: credential parsing failed kp={kp_id}");
                return None;
            }
        };
        let (_uid, nick) = decode_credential(&identity);
        if nick.is_empty() {
            None
        } else {
            Some(nick)
        }
    }

    fn decrypt_join_text(&self, r: &JoinRequestRecord) -> Result<String> {
        crypto::decrypt_text_with_key(
            &r.text_ct,
            &r.text_iv,
            &r.text_tag,
            &r.text_wrapped_key,
            &self.priv_key,
        )
    }

    /// Allow or deny a join request.
    /// `allow` only flips the business status to approved; the real join happens when [`GroupService::approve_and_add`] runs the MLS Add.
    pub fn decide_join_request(
        &self,
        group_id: &str,
        request_id: &str,
        allow: bool,
    ) -> Result<()> {
        self.transport
            .decide_join_request(group_id, request_id, allow)
    }

    /// Approve and run the MLS Add: produce Commit + Welcome, submit them, and return `(new epoch, added user)`.
    pub fn approve_and_add(&self, group_id: &str, request_id: &str) -> Result<(u64, String)> {
        // 1. Fetch the request to get the applicant and the KeyPackage
        let rows = self.transport.list_join_requests(group_id)?;
        let req = rows
            .iter()
            .find(|r| r.request_id == request_id)
            .context("the request does not exist")?;
        let applicant = req.applicant.clone();
        let kp_b64 = self
            .transport
            .fetch_key_package(group_id, &req.kp_id)?;
        let kp_bytes = base64_decode(&kp_b64)?;

        // 2. Business status -> approved (the server does **not** write the member table at this point)
        self.decide_join_request(group_id, request_id, true)?;

        // 3. Run the Add locally (needs the current group state)
        let mut adapter = self.open_adapter(group_id)?;
        let parent_epoch = adapter.epoch();
        let (commit_bytes, welcome_bytes) = adapter
            .add_members(&[kp_bytes])
            .map_err(|e| anyhow::anyhow!("adding the member failed: {e}"))?;
        let new_epoch = adapter.epoch();

        // 4. Push Commit + Welcome (only after this does the server add the applicant to the member table)
        let commit_b64 = base64_encode(&commit_bytes);
        self.transport.push_commit(
            group_id,
            new_epoch,
            parent_epoch,
            "commit",
            &commit_b64,
            &crypto::sha256_hex(&commit_bytes),
        )?;
        let welcome_b64 = base64_encode(&welcome_bytes);
        self.transport.push_welcome(
            group_id,
            &applicant,
            &welcome_b64,
            &crypto::sha256_hex(&welcome_bytes),
            new_epoch,
        )?;

        // 5. Persist locally: the member table follows the MLS ratchet tree (including the new applicant)
        self.persist_adapter(group_id, &adapter, new_epoch)?;
        self.sync_members_from_mls(group_id, &adapter, new_epoch)?;
        let _ = applicant.clone();
        Ok((new_epoch, applicant))
    }

    // Sending and receiving messages

    /// Send one group message; returns the server-assigned `seq`.
    pub fn send_text(&self, group_id: &str, text: &str) -> Result<u64> {
        let mut adapter = self.open_adapter(group_id)?;
        let epoch = adapter.epoch();
        let ct = adapter
            .seal_text(text.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to encrypt the group message: {e}"))?;
        let msg_id = crypto::generate_msg_id();
        let seq = self.transport.send_group_message(
            group_id,
            epoch,
            &msg_id,
            &base64_encode(&ct),
            "",
            "",
        )?;
        // My own messages do not count as unread, but they still need a local row (otherwise they would not display)
        let st = self
            .store
            .get_group(self.sid(), group_id)?
            .context("no such group locally")?;
        self.store.insert_group_message(
            self.sid(),
            group_id,
            seq,
            &msg_id,
            &self.username,
            text,
            st.current_epoch,
            MSG_OK,
        )?;
        self.persist_adapter(group_id, &adapter, epoch)?;
        Ok(seq)
    }

    /// Pull and decrypt group messages: catch up on Commits first, then pull; returns the number of newly added rows.
    /// If the server reports the group dissolved or missing, the local copy is removed before erroring, so no permanently failing zombie group lingers on the session tree.
    pub fn sync_group(&self, group_id: &str) -> Result<usize> {
        match self.sync_group_inner(group_id) {
            Ok(n) => Ok(n),
            Err(e) if group_is_gone(&e) => {
                self.store.delete_group(self.sid(), group_id)?;
                bail!("the group has been dissolved (the server returned {e:#}), removed locally");
            }
            // The group exists but the server no longer counts me as a member (likely removed by the owner): drop the local copy, no zombie groups.
            Err(e) if group_kicked_me(&e) => {
                self.store.delete_group(self.sid(), group_id)?;
                bail!("you are no longer in this group (possibly removed by the owner), cleared locally");
            }
            Err(e) => Err(e),
        }
    }

    fn sync_group_inner(&self, group_id: &str) -> Result<usize> {
        // 1. Catch up the epoch first: process other members' Commits
        self.sync_commits(group_id)?;

        // 1'. Roles, then reconcile -- order matters: succession may have happened while I was offline, leaving the
        // server calling me owner while local says member; the stale role would hit `reconcile_departed`'s gate and departed members would never be removed.
        if let Ok(adapter) = self.open_adapter(group_id) {
            let mut adapter = adapter;
            let _ = self.refresh_my_role(group_id);
            // A role change (**owner transfer**) produces no MLS commit, and an empty log returns early above, so the
            // full role refresh must sit on this always-taken path or F9 would show stale roles forever.
            if let Err(e) = self.refresh_member_roles(group_id) {
                crate::tui_log!("failed to refresh member roles group={group_id}: {e:#}");
            }
            let _ = self.reconcile_departed(group_id, &mut adapter);
        }

        // 2. Then pull messages and decrypt them by epoch
        let since = self.store.group_last_seq(self.sid(), group_id)?;
        let pulled = self.transport.list_messages_since(group_id, since, 200)?;

        // Server deletion lower bound: falling too far behind means truncation, which must not pass silently
        if pulled.min_seq > since {
            self.store
                .set_group_min_seq(self.sid(), group_id, pulled.min_seq)?;
        }

        let mut adapter = self.open_adapter(group_id)?;
        let joined_epoch = self
            .store
            .get_group(self.sid(), group_id)?
            .map(|g| g.joined_epoch)
            .unwrap_or(0);

        let mut added = 0usize;
        let mut max_seq = since;
        for m in &pulled.messages {
            max_seq = max_seq.max(m.seq);
            if self.message_exists(group_id, m.seq)? {
                continue;
            }
            // Pre-join messages are undecryptable (MLS forward secrecy); store a placeholder instead of erroring
            if m.epoch < joined_epoch {
                self.store.insert_group_message(
                    self.sid(),
                    group_id,
                    m.seq,
                    &m.msg_id,
                    &m.sender,
                    "",
                    m.epoch,
                    crate::group::storage::MSG_GAP,
                )?;
                added += 1;
                continue;
            }
            match self.open_and_store(group_id, &mut adapter, m) {
                Ok(true) => added += 1,
                Ok(false) => {}
                Err(e) => {
                    // One bad message must not abort the batch; the caller decides how to surface the log line
                    crate::tui_log!("failed to decrypt the group message group={group_id} seq={} : {e:#}", m.seq);
                }
            }
        }

        let epoch = adapter.epoch();
        self.persist_adapter(group_id, &adapter, epoch)?;

        // 3. Ack only after success (advances the server's deletion watermark)
        if max_seq > since {
            self.transport.ack_messages(group_id, max_seq)?;
            self.store.set_group_last_seq(self.sid(), group_id, max_seq)?;
        }
        Ok(added)
    }

    fn message_exists(&self, group_id: &str, seq: u64) -> Result<bool> {
        Ok(self
            .store
            .list_group_messages(self.sid(), group_id, 0)?
            .iter()
            .any(|m| m.seq == seq))
    }

    fn open_and_store(
        &self,
        group_id: &str,
        adapter: &mut MlsAdapter,
        m: &GroupMsgRecord,
    ) -> Result<bool> {
        let ct = base64_decode(&m.ciphertext)?;
        match adapter
            .open(&ct)
            .map_err(|e| anyhow::anyhow!("failed to process the group message: {e}"))?
        {
            Opened::Application { plaintext, epoch } => {
                let text = String::from_utf8_lossy(&plaintext).to_string();
                let inserted = self.store.insert_group_message(
                    self.sid(),
                    group_id,
                    m.seq,
                    &m.msg_id,
                    &m.sender,
                    &text,
                    epoch,
                    MSG_OK,
                )?;
                // Only messages from others count as unread
                if inserted && m.sender != self.username {
                    self.store.bump_group_unread(self.sid(), group_id, 1)?;
                }
                Ok(inserted)
            }
            Opened::Commit { staged, .. } => {
                // A Commit mixed into the message stream: merge it (the epoch advances)
                adapter
                    .merge_staged(*staged)
                    .map_err(|e| anyhow::anyhow!("failed to merge the Commit: {e}"))?;
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Catch the epoch up: process and merge each Commit after `since_epoch`.
    fn sync_commits(&self, group_id: &str) -> Result<()> {
        let st = self
            .store
            .get_group(self.sid(), group_id)?
            .context("no such group locally")?;
        let logs = self.transport.list_commits_since(group_id, st.current_epoch)?;
        if logs.is_empty() {
            return Ok(());
        }
        let mut adapter = self.open_adapter(group_id)?;
        for l in &logs {
            // Everything in the control log except Welcome must be processed: Add/Remove push "commit", nickname/identity updates push "update".
            // Filtering on `kind == "commit"` is wrong — it silently skipped updates, so nickname changes stayed invisible to others.
            if l.kind == "welcome" {
                continue;
            }
            let data = base64_decode(&l.data_b64)?;
            // Verify the digest (the server is an opaque forwarder, so the client must check it itself)
            if crypto::sha256_hex(&data) != l.data_hash {
                bail!("Commit digest mismatch (possibly tampered with) seq={}", l.seq);
            }
            match adapter
                .open(&data)
                .map_err(|e| anyhow::anyhow!("Commit validation failed (possibly malicious): {e}"))?
            {
                Opened::Commit { staged, .. } => {
                    let ep = adapter
                        .merge_staged(*staged)
                        .map_err(|e| anyhow::anyhow!("failed to merge the Commit: {e}"))?;
                    self.store.set_group_epoch(self.sid(), group_id, ep)?;
                }
                Opened::Application { .. } => {}
                _ => {}
            }
        }
        let ep = adapter.epoch();
        self.persist_adapter(group_id, &adapter, ep)?;
        // The member table must be refreshed after merging Commits: they may contain Add/Remove and the ratchet tree has changed, so without a refresh existing members never learn about new members or their nicknames.
        self.sync_members_from_mls(group_id, &adapter, ep)?;

        // Missing from the ratchet tree after merging = I was removed: the local MLS state is unusable (openmls marks it
        // Inactive), so the local copy must be dropped and reported honestly, or a permanently failing zombie group stays in the UI.
        if !self.is_member(group_id)? {
            self.store.delete_group(self.sid(), group_id)?;
            bail!("you have been removed from the group");
        }
        Ok(())
    }

    // Group info

    pub fn group_detail(&self, group_id: &str) -> Result<GroupDetail> {
        self.transport.get_group(group_id)
    }

    /// Local group list.
    pub fn local_groups(&self) -> Result<Vec<GroupState>> {
        let rows = self.store.list_groups(self.sid())?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let last = self.store.group_last_seq(self.sid(), &r.group_id)?;
            out.push(r.to_state(last));
        }
        Ok(out)
    }

    /// Local group members (with roles).
    pub fn local_members(&self, group_id: &str) -> Result<Vec<super::storage::GroupMemberRow>> {
        self.store.list_group_members(self.sid(), group_id)
    }

    /// Display name for a member in this group: the nickname when available, otherwise the user_id.
    pub fn member_display_name(&self, group_id: &str, user_id: &str) -> String {
        self.store
            .group_member_nickname(self.sid(), group_id, user_id)
            .ok()
            .flatten()
            .unwrap_or_else(|| user_id.to_string())
    }

    /// Local group messages (`limit = 0` means all).
    pub fn local_messages(&self, group_id: &str, limit: usize) -> Result<Vec<GroupMessageRow>> {
        self.store.list_group_messages(self.sid(), group_id, limit)
    }

    /// Local group epoch, used to tell whether a sync **advanced group state**:
    /// rename/add/kick are all MLS commits that advance the epoch but produce no new messages.
    pub fn local_epoch(&self, group_id: &str) -> Option<u64> {
        self.store
            .get_group(self.sid(), group_id)
            .ok()
            .flatten()
            .map(|g| g.current_epoch)
    }

    /// Decrypt the group name: prefer the MLS group context (updated along with the Commit on rename), fall back to local `name_enc`.
    pub fn decrypt_group_name(&self, group_id: &str) -> Result<Option<String>> {
        let row = self.store.get_group(self.sid(), group_id)?;
        let adapter = self.open_adapter(group_id)?;

        if let Some(payload) = adapter.name_ext() {
            if let Some((_, Some(name))) = parse_name_ext(&payload) {
                return Ok(Some(name));
            }
        }
        let Some(name_enc) = row.and_then(|r| r.name_enc) else {
            return Ok(None);
        };
        if name_enc.is_empty() {
            return Ok(None);
        }
        let key = adapter
            .name_key()
            .context("the MLS group context is missing the group name key")?;
        let plain = open_blob(&key, &name_enc)?;
        Ok(Some(String::from_utf8(plain).context("group name is not valid UTF-8")?))
    }

    /// Rename: one GroupContextExtensions commit broadcast to the group; returns the new epoch.
    /// Owner only. Other members see the new name once `sync_commits` merges it, and later joiners get it from the Welcome's group context.
    pub fn set_group_name(&self, group_id: &str, new_name: &str) -> Result<u64> {
        let new_name = new_name.trim();
        if new_name.is_empty() {
            bail!("group name must not be empty");
        }
        if new_name.chars().count() > 64 {
            bail!("group name is too long (at most 64 characters)");
        }
        // As in `remove_member`: calibrate the role from the server roster first, so a stale role cannot cause a false rejection
        let _ = self.refresh_my_role(group_id);
        let state = self
            .store
            .get_group(self.sid(), group_id)?
            .context("no such group locally")?;
        if state.my_role != GroupRole::Owner {
            bail!("only the owner can change the group name (I am currently {})", state.my_role.as_str());
        }

        let mut adapter = self.open_adapter(group_id)?;
        let name_key = adapter
            .name_key()
            .context("the MLS group context is missing the group name key")?;
        let name_ext = build_name_ext(&name_key, new_name)?;

        let parent_epoch = adapter.epoch();
        let commit_bytes = adapter
            .set_name_ext(&name_ext)
            .map_err(|e| anyhow::anyhow!("failed to rename the group: {e}"))?;
        let new_epoch = adapter.epoch();

        self.transport.push_commit(
            group_id,
            new_epoch,
            parent_epoch,
            "update",
            &base64_encode(&commit_bytes),
            &crypto::sha256_hex(&commit_bytes),
        )?;

        // Refresh name_enc locally too, keeping the server metadata and the legacy client's fallback path in step
        let name_enc = seal_blob(&name_key, new_name.as_bytes())?;
        self.store
            .set_group_name_enc(self.sid(), group_id, &name_enc)?;
        self.persist_adapter(group_id, &adapter, new_epoch)?;
        Ok(new_epoch)
    }

    /// Whether the local roster contains me (separates "joined" from "applied only").
    pub fn is_member(&self, group_id: &str) -> Result<bool> {
        Ok(self
            .local_members(group_id)?
            .iter()
            .any(|m| &m.user_id == &self.username))
    }

    // Internal helpers

    fn load_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        Ok(match self.store.get_group(self.sid(), group_id)? {
            Some(r) => {
                let last = self.store.group_last_seq(self.sid(), group_id)?;
                Some(r.to_state(last))
            }
            None => None,
        })
    }

    /// Open the local MLS group (restoring state from SQLCipher).
    fn open_adapter(&self, group_id: &str) -> Result<MlsAdapter> {
        let (_, state_blob, signer_blob) = self
            .store
            .load_mls_state(self.sid(), group_id)?
            .with_context(|| format!("the local MLS state for the group is missing group={group_id}"))?;
        MlsAdapter::restore(RestoreInput {
            signer_blob: &signer_blob,
            state_blob: &state_blob,
            group_id: group_id.as_bytes(),
        })
        .map_err(|e| anyhow::anyhow!("failed to restore the group MLS state: {e}"))
    }

    /// Refresh the local member table from the MLS group's leaves (existing roles are kept, unknown users become member).
    fn sync_members_from_mls(
        &self,
        group_id: &str,
        adapter: &MlsAdapter,
        epoch: u64,
    ) -> Result<()> {
        let existing: std::collections::HashMap<String, GroupRole> = self
            .local_members(group_id)?
            .into_iter()
            .map(|m| (m.user_id, m.role))
            .collect();
        let mut next: Vec<(String, GroupRole, u64, String)> = Vec::new();
        for id_bytes in adapter.member_identities() {
            let Ok(identity) = String::from_utf8(id_bytes) else { continue };
            // credential identity = `user_id` (+ SEP + nickname)
            let (uid, nickname) = decode_credential(&identity);
            let role = existing.get(&uid).copied().unwrap_or(GroupRole::Member);
            next.push((uid, role, epoch, nickname));
        }
        // **Replace wholesale** rather than upserting one by one: anyone no longer in the ratchet tree must be dropped from the roster.
        self.store
            .replace_group_members(self.sid(), group_id, &next)?;
        // With the MLS members in place, refresh roles from the server once more: transfers and kicks both change roles
        if let Err(e) = self.refresh_member_roles(group_id) {
            // Not fatal (members and messages still work) but worth a log line: a failed role refresh makes F9 show stale roles
            crate::tui_log!("failed to refresh member roles group={group_id}: {e:#}");
        }
        Ok(())
    }

    fn persist_adapter(&self, group_id: &str, adapter: &MlsAdapter, epoch: u64) -> Result<()> {
        let state_blob = adapter
            .export_state()
            .map_err(|e| anyhow::anyhow!("failed to export group state: {e}"))?;
        let signer_blob = self
            .store
            .load_mls_state(self.sid(), group_id)?
            .map(|(_, _, s)| s)
            .context("missing the signer blob, cannot persist")?;
        self.store
            .save_mls_state(self.sid(), group_id, epoch, &state_blob, &signer_blob)?;
        self.store.set_group_epoch(self.sid(), group_id, epoch)?;
        Ok(())
    }

    /// For UI display: the group member list (server-authoritative).
    pub fn remote_members(&self, group_id: &str) -> Result<Vec<MemberInfo>> {
        Ok(self.transport.get_group(group_id)?.members)
    }


    /// Whether the group still exists on the server (not dissolved); used to clean up stale "applied but never approved" records.
    /// A failed query returns Err (non-members get NOT_GROUP_MEMBER, which means the group is alive), so callers must not delete local data on that basis.
    pub fn group_exists(&self, group_id: &str) -> Result<bool> {
        match self.transport.get_group(group_id) {
            Ok(_) => Ok(true),
            Err(e) if group_is_gone(&e) => Ok(false),
            Err(_) => Ok(true),
        }
    }

    /// Clear only the local record (no server notification); used to clean up stale join records.
    pub fn forget_group(&self, group_id: &str) -> Result<()> {
        self.store.delete_group(self.sid(), group_id)
    }

    /// Leave the group.
    /// A leaver cannot remove itself from the MLS tree — openmls rejects `remove_members(&[self])` with `CreateCommitError(CannotRemoveSelf)`.
    /// So it takes two steps: (1) drop the server member row and the local copy here, leaving immediately; (2) the owner notices during sync that someone is
    /// still in the MLS tree but off the server roster and submits the Remove (see `reconcile_departed`). Step (2) is essential, or the leaver's leaf stays in everyone's ratchet tree, MLS never rotates keys, and they can still decrypt later messages.
    pub fn leave_group(&self, group_id: &str, successor: Option<&str>) -> Result<()> {
        // An owner with remaining members must name a successor (the server rejects with SUCCESSOR_REQUIRED); block it locally first.
        let _ = self.refresh_my_role(group_id);
        let state = self.store.get_group(self.sid(), group_id)?;
        if let Some(st) = &state {
            if st.my_role == GroupRole::Owner {
                let others = self
                    .local_members(group_id)?
                    .into_iter()
                    .filter(|m| m.user_id != self.username)
                    .count();
                if others > 0 && successor.map(|s| s.trim().is_empty()).unwrap_or(true) {
                    bail!(
                        "you are the owner; you must designate a new owner before leaving ({others} other members in the group)"
                    );
                }
            }
        }

        self.transport.leave_group(group_id, successor)?;
        self.store.delete_group(self.sid(), group_id)?;
        Ok(())
    }

    /// Reconcile: drop anyone still in my MLS tree but no longer on the server roster.
    /// The roster is authoritative for "who is still allowed" and the tree for keys, so removing only people the server already dropped is no
    /// privilege escalation. Owner only (the server allows owner/admin Commits; plain members skip). Leave notifications are best-effort, backstopped by the persisted server todo.
    fn reconcile_departed(&self, group_id: &str, adapter: &mut MlsAdapter) -> Result<bool> {
        // Only the owner pushes Commits here (the server allows owner/admin); plain members would otherwise fire a doomed
        // request on every sync. The cost is that an owner must be online for leavers to actually leave the ratchet tree.
        let role = self
            .store
            .get_group(self.sid(), group_id)?
            .map(|g| g.my_role)
            .unwrap_or(GroupRole::Member);
        if role != GroupRole::Owner {
            return Ok(false);
        }

        // The server's registered "pending removal" todo: left behind when someone leaves while the owner is offline, and a durable reason to sync this group (pushes are lost while offline).
        let pending = self
            .transport
            .list_pending_removals(group_id)
            .unwrap_or_default();

        let detail = match self.transport.get_group(group_id) {
            Ok(d) => d,
            // No roster (network/permission) means do nothing and retry on the next sync
            Err(_) => return Ok(false),
        };
        let on_server: std::collections::HashSet<String> =
            detail.members.iter().map(|m| m.user_id.clone()).collect();
        let mine = self.username.clone();

        let mut gone: Vec<openmls::prelude::LeafNodeIndex> = Vec::new();
        for (idx, ident) in adapter.member_leaf_indices() {
            let Ok(ident) = String::from_utf8(ident) else { continue };
            let (uid, _) = decode_credential(&ident);
            // Not on the server roster means I was removed; the "kicked" branch of sync handles it
            if uid == mine {
                continue;
            }
            if !on_server.contains(&uid) {
                gone.push(idx);
            }
        }
        if gone.is_empty() {
            // Rosters agree (every todo entry is already out of the ratchet tree) -> just clear the todo
            if !pending.is_empty() {
                let _ = self.transport.clear_pending_removals(group_id);
            }
            return Ok(false);
        }

        let parent_epoch = adapter.epoch();
        let commit = adapter
            .remove_members(&gone)
            .map_err(|e| anyhow::anyhow!("failed to remove a departed member: {e}"))?
            .context("MLS produced no commit")?;
        let new_epoch = adapter.epoch();
        self.transport.push_commit(
            group_id,
            new_epoch,
            parent_epoch,
            "commit",
            &base64_encode(&commit),
            &crypto::sha256_hex(&commit),
        )?;
        self.persist_adapter(group_id, adapter, new_epoch)?;
        self.sync_members_from_mls(group_id, adapter, new_epoch)?;
        // The commit is pushed, so the todo can be cleared (a failure is harmless: the next sync reconciles to empty and clears it)
        let _ = self.transport.clear_pending_removals(group_id);
        Ok(true)
    }

    /// Refresh **every** member's local role from the server's authoritative role table.
    /// `refresh_my_role` covers only me, and the MLS tree carries no roles, so without this other members' roles stay stale and F9 shows the old owner after a transfer.
    fn refresh_member_roles(&self, group_id: &str) -> Result<()> {
        for (uid, role) in self.transport.member_roles(group_id)? {
            let r = match role.as_str() {
                "owner" => GroupRole::Owner,
                "admin" => GroupRole::Admin,
                _ => GroupRole::Member,
            };
            self.store.set_member_role(self.sid(), group_id, &uid, r)?;
        }
        Ok(())
    }

    /// Refresh my role in this group from the server and update local state so the UI repaints.
    /// Succession or promotion to admin may happen while I am offline; a stale role makes `can_commit()` false, which blocks rename/kick/reconcile locally.
    fn refresh_my_role(&self, group_id: &str) -> Result<()> {
        let detail = self.transport.get_group(group_id)?;
        let Some(me) = detail.members.iter().find(|m| m.user_id == self.username) else {
            return Ok(());
        };
        let role: GroupRole = me.role.parse().unwrap_or(GroupRole::Member);
        let cur = self
            .store
            .get_group(self.sid(), group_id)?
            .map(|g| g.my_role);
        if cur != Some(role) {
            self.store.set_group_role(self.sid(), group_id, role)?;
            crate::tui_log!(
                "group role updated group={group_id} -> {} (refreshed from the server roster)",
                role.as_str()
            );
        }
        Ok(())
    }

    /// Whether the group has a pending-removal todo (owner/admin only; everyone else gets false).
    /// Startup uses it to decide whether to sync this group proactively: leave notifications are best-effort, while the todo is persisted.
    pub fn has_pending_removals(&self, group_id: &str) -> bool {
        self.transport
            .list_pending_removals(group_id)
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }

    /// Owner starts a transfer: name a successor and wait for them to confirm in the approval list.
    /// Unlike "leave and name a successor", I stay owner and keep approving joins until the designee confirms,
    /// so a standalone transfer never triggers "joins temporarily not allowed".
    pub fn start_owner_transfer(&self, group_id: &str, designee: &str) -> Result<()> {
        let _ = self.refresh_my_role(group_id);
        let state = self
            .store
            .get_group(self.sid(), group_id)?
            .context("no such group locally")?;
        if state.my_role != GroupRole::Owner {
            bail!("only the owner can transfer ownership (I am currently {})", state.my_role.as_str());
        }
        if designee == self.username {
            bail!("cannot transfer ownership to yourself");
        }
        self.transport.start_owner_transfer(group_id, designee)
    }

    /// View the group's pending transfer (visible to the designee and the current owner).
    pub fn pending_owner_transfer(
        &self,
        group_id: &str,
    ) -> Result<Option<super::transport::OwnerTransferInfo>> {
        self.transport.pending_owner_transfer(group_id)
    }

    /// Designee confirms the transfer; on accept I become owner and the previous owner drops to a plain member.
    pub fn decide_owner_transfer(&self, group_id: &str, accept: bool) -> Result<()> {
        self.transport.decide_owner_transfer(group_id, accept)?;
        // Calibrate the role from the server roster immediately, so the UI does not keep showing the old one
        let _ = self.refresh_my_role(group_id);
        Ok(())
    }

    /// Owner removes a member (kick); returns the new epoch.
    /// Same flow as leaving — produce and push an MLS Remove commit first (rotating keys for the whole group, so the target can no longer read new messages), then have the server delete the member row.
    /// The order cannot be reversed: a Remove commit requires the sender to still be a member.
    pub fn remove_member(&self, group_id: &str, target_user: &str) -> Result<u64> {
        // Refresh the role first: succession may have happened since my last sync, and a stale role would block a legitimate "new owner kicks" (with a misleading message).
        let _ = self.refresh_my_role(group_id);
        let state = self
            .store
            .get_group(self.sid(), group_id)?
            .context("no such group locally")?;
        if state.my_role != GroupRole::Owner {
            bail!("only the owner can remove members (I am currently {})", state.my_role.as_str());
        }
        if target_user == self.username {
            bail!("cannot remove yourself -- use the leave-group action instead");
        }

        let mut adapter = self.open_adapter(group_id)?;
        let leaf = adapter
            .member_leaf_indices()
            .into_iter()
            .find(|(_, ident)| {
                let ident = String::from_utf8_lossy(ident).to_string();
                decode_credential(&ident).0 == target_user
            })
            .map(|(idx, _)| idx)
            .with_context(|| format!("{target_user} is not in this group's MLS member tree"))?;

        let parent_epoch = adapter.epoch();
        let commit = adapter
            .remove_members(&[leaf])
            .map_err(|e| anyhow::anyhow!("failed to remove the member: {e}"))?
            .context("MLS produced no commit")?;
        let new_epoch = adapter.epoch();

        self.transport.push_commit(
            group_id,
            new_epoch,
            parent_epoch,
            "commit",
            &base64_encode(&commit),
            &crypto::sha256_hex(&commit),
        )?;
        self.persist_adapter(group_id, &adapter, new_epoch)?;
        self.sync_members_from_mls(group_id, &adapter, new_epoch)?;

        // Cryptographically removed; now drop the server member row so the target cannot even fetch ciphertext.
        self.transport.kick_member(group_id, target_user)?;
        Ok(new_epoch)
    }

    /// Dissolve the group (owner only); on success all local data for it is cleared.
    pub fn dissolve_group(&self, group_id: &str) -> Result<()> {
        self.transport.dissolve_group(group_id)?;
        self.store.delete_group(self.sid(), group_id)?;
        Ok(())
    }
}

// Encoding helpers

pub fn base64_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode failed")
}

/// Whether the server explicitly says the group is dissolved or missing (`GROUP_DISSOLVED` / `GROUP_NOT_FOUND`).
/// The client treats that as "the group is gone" rather than a retryable failure.
pub fn group_is_gone(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("GROUP_DISSOLVED") || s.contains("GROUP_NOT_FOUND")
}

/// Whether the server explicitly says **I** am no longer a member (`NOT_GROUP_MEMBER`): the group is alive, I was removed.
/// Treating only `GROUP_DISSOLVED`/`GROUP_NOT_FOUND` as "time to clean up" would leave a permanently failing zombie group.
pub fn group_kicked_me(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}");
    s.contains("NOT_GROUP_MEMBER")
}

/// Pack `iv || ct || tag` into a self-contained blob (name extension payload = `name key (32B) || AES-GCM(name key, name)`).
/// The server stores opaque bytes and holds no key, so the format is the client's own. Putting the ciphertext in the
/// MLS group context lets new members read the current name straight from the Welcome, syncs a rename to the whole group in one Commit, and keeps the name invisible to the server.
pub fn build_name_ext(name_key: &[u8], name: &str) -> Result<Vec<u8>> {
    let mut out = name_key.to_vec();
    out.extend_from_slice(&seal_blob(name_key, name.as_bytes())?);
    Ok(out)
}

/// Parse the name extension payload into `(name key, Option<name>)`.
/// A 32-byte payload means "key only, no name" (early groups), and the caller falls back to local `name_enc`.
pub fn parse_name_ext(payload: &[u8]) -> Option<(Vec<u8>, Option<String>)> {
    if payload.len() < adapter::NAME_KEY_LEN {
        return None;
    }
    let key = payload[..adapter::NAME_KEY_LEN].to_vec();
    let rest = &payload[adapter::NAME_KEY_LEN..];
    if rest.is_empty() {
        return Some((key, None));
    }
    match open_blob(&key, rest) {
        Ok(bytes) => Some((key, String::from_utf8(bytes).ok())),
        // A corrupt ciphertext (e.g. a hand-edited DB) must not make the whole group list unreadable: degrade to "no name"
        Err(_) => Some((key, None)),
    }
}

pub fn seal_blob(key: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let (ct_b64, iv_b64, tag_b64) = crypto::aes_gcm_encrypt(key, plain)?;
    let mut out = base64_decode(&iv_b64)?;
    out.extend_from_slice(&base64_decode(&ct_b64)?);
    out.extend_from_slice(&base64_decode(&tag_b64)?);
    Ok(out)
}

/// Open a blob produced by [`seal_blob`]. The IV is a fixed 12 bytes and the tag 16 (see the constants in `crypto`).
pub fn open_blob(key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    const IV: usize = 12;
    const TAG: usize = 16;
    if blob.len() < IV + TAG {
        bail!("ciphertext blob is too short ({} bytes)", blob.len());
    }
    let iv = &blob[..IV];
    let tag = &blob[blob.len() - TAG..];
    let ct = &blob[IV..blob.len() - TAG];
    crypto::aes_gcm_decrypt(key, &base64_encode(ct), &base64_encode(iv), &base64_encode(tag))
}
