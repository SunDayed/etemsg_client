//! Group end-to-end tests: the full create/approve/join/send/rotate flow against an in-memory fake server.
//!
//! The fake models only server semantics (authorization, todos, transfers); it never parses MLS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};

use super::service::GroupService;
use super::transport::*;
use crate::store::Store;

// In-memory fake server

#[derive(Default)]
struct FakeState {
    groups: HashMap<String, FakeGroup>,
    /// kp_id -> (user_id, kp_b64, consumed)
    key_packages: HashMap<String, (String, String, bool)>,
    join_requests: Vec<JoinRequestRecord>,
    /// group_id -> control log
    logs: HashMap<String, Vec<MlsLogRecord>>,
    /// group_id -> group messages (one copy for the whole group)
    messages: HashMap<String, Vec<GroupMsgRecord>>,
    /// (group_id, user_id) -> acked position
    cursors: HashMap<(String, String), u64>,
    next_seq: HashMap<String, u64>,
    /// Per-group min_seq (simulating queue trimming)
    min_seq: HashMap<String, u64>,
    /// group_id -> pending removals (registered when someone leaves; the owner submits the Remove commit later)
    pending_removals: HashMap<String, Vec<String>>,
    /// (group_id, prev_owner, designee, state); state: pending/accepted/declined
    transfers: Vec<(String, String, String, String)>,
    /// Who is calling (binds a user_id to each request)
    current_user: String,
}

struct FakeGroup {
    detail: GroupDetail,
    /// active / dissolved (the real server has groups.state, which GroupDetail omits)
    state: String,
}

#[derive(Default)]
struct FakeServer {
    st: Mutex<FakeState>,
}

impl FakeServer {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn as_user(self: &Arc<Self>, u: &str) -> UserView {
        UserView { srv: self.clone(), user: u.to_string() }
    }
}

/// Access the fake server as one user (standing in for a signed request: only the identity matters here).
struct UserView {
    srv: Arc<FakeServer>,
    user: String,
}

impl GroupTransport for UserView {
    fn create_group(&self, req: &CreateGroupReq) -> Result<CreateGroupResp> {
        let mut st = self.srv.st.lock().unwrap();
        if st.groups.contains_key(&req.group_id) {
            bail!("group already exists");
        }
        st.groups.insert(
            req.group_id.clone(),
            FakeGroup {
                detail: GroupDetail {
                    group_id: req.group_id.clone(),
                    name_enc: Some(req.name_enc.clone()),
                    creator: self.user.clone(),
                    current_epoch: 0,
                    min_seq: 0,
                    members: vec![MemberInfo {
                        user_id: self.user.clone(),
                        role: "owner".into(),
                        joined_epoch: 0,
                    }],
                },
                state: "active".to_string()
            },
        );
        st.next_seq.insert(req.group_id.clone(), 0);
        Ok(CreateGroupResp { group_id: req.group_id.clone() })
    }

    fn get_group(&self, group_id: &str) -> Result<GroupDetail> {
        let st = self.srv.st.lock().unwrap();
        let g = st.groups.get(group_id).ok_or_else(|| anyhow::anyhow!("group not found"))?;
        if !g.detail.members.iter().any(|m| m.user_id == self.user) {
            bail!("non-members may not view this");
        }
        Ok(g.detail.clone())
    }

    fn search_by_id(&self, group_id: &str) -> Result<Vec<GroupSearchHit>> {
        let st = self.srv.st.lock().unwrap();
        Ok(st
            .groups
            .get(group_id)
            .map(|g| {
                // The real server returns the current owner (the approver), which differs from creator after a transfer
                let owner = g
                    .detail
                    .members
                    .iter()
                    .find(|m| m.role == "owner")
                    .map(|m| m.user_id.clone())
                    .unwrap_or_default();
                let owner_public_key = if owner.is_empty() {
                    String::new()
                } else {
                    test_creator_pubkey(&owner)
                };
                vec![GroupSearchHit {
                    group_id: group_id.to_string(),
                    name_enc: g.detail.name_enc.clone(),
                    creator: g.detail.creator.clone(),
                    // The "public key" is injected by the test (see CREATOR_PUBKEYS)
                    creator_public_key: test_creator_pubkey(&g.detail.creator),
                    owner,
                    owner_public_key,
                    member_count: g.detail.members.len() as u64,
                }]
            })
            .unwrap_or_default())
    }

    fn upload_key_package(
        &self,
        _group_id: &str,
        kp_id: &str,
        kp_b64: &str,
        _kp_hash: &str,
    ) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        st.key_packages
            .insert(kp_id.to_string(), (self.user.clone(), kp_b64.to_string(), false));
        Ok(())
    }

    fn fetch_key_package(&self, _group_id: &str, kp_id: &str) -> Result<String> {
        let st = self.srv.st.lock().unwrap();
        let (_, kp, _) = st
            .key_packages
            .get(kp_id)
            .ok_or_else(|| anyhow::anyhow!("KeyPackage not found"))?;
        Ok(kp.clone())
    }

    fn submit_join_request(&self, req: &JoinRequestRecord) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        // Owner left and the successor has not confirmed -> no owner -> joins rejected with GROUP_OWNER_UPDATING
        {
            let has_pending = st
                .transfers
                .iter()
                .any(|(g, _, _, state)| g == &req.group_id && state == "pending");
            let has_owner = st
                .groups
                .get(&req.group_id)
                .map(|g| g.detail.members.iter().any(|m| m.role == "owner"))
                .unwrap_or(false);
            if has_pending && !has_owner {
                anyhow::bail!("GROUP_OWNER_UPDATING: the group owner is being updated, joining is temporarily disabled");
            }
        }
        // One pending request per person per group
        if st.join_requests.iter().any(|r| {
            r.group_id == req.group_id && r.applicant == req.applicant && r.status == "pending"
        }) {
            bail!("there is already a pending request");
        }
        st.join_requests.push(req.clone());
        Ok(())
    }

    fn list_join_requests(&self, group_id: &str) -> Result<Vec<JoinRequestRecord>> {
        let st = self.srv.st.lock().unwrap();
        let g = st.groups.get(group_id).ok_or_else(|| anyhow::anyhow!("group not found"))?;
        // owner/admin only
        let me = g.detail.members.iter().find(|m| m.user_id == self.user);
        match me {
            Some(m) if m.role == "owner" || m.role == "admin" => {}
            _ => bail!("no approval permission"),
        }
        Ok(st
            .join_requests
            .iter()
            .filter(|r| r.group_id == group_id && r.status == "pending")
            .cloned()
            .collect())
    }

    fn decide_join_request(&self, group_id: &str, request_id: &str, allow: bool) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let idx = st
            .join_requests
            .iter()
            .position(|r| r.request_id == request_id && r.group_id == group_id)
            .ok_or_else(|| anyhow::anyhow!("the request does not exist"))?;
        if st.join_requests[idx].status != "pending" {
            bail!("the request has already been handled");
        }
        st.join_requests[idx].status = if allow { "approved".into() } else { "denied".into() };
        Ok(())
    }

    fn push_commit(
        &self,
        group_id: &str,
        epoch: u64,
        _parent_epoch: u64,
        kind: &str,
        commit_b64: &str,
        data_hash: &str,
    ) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        if !st.groups.contains_key(group_id) {
            bail!("group not found");
        }
        // Write the log first (borrowing logs), then update group state, avoiding two simultaneous mutable borrows of st
        let seq = {
            let logs = st.logs.entry(group_id.to_string()).or_default();
            let seq = logs.len() as u64 + 1;
            logs.push(MlsLogRecord {
                seq,
                epoch,
                kind: kind.into(),
                sender: self.user.clone(),
                target: String::new(),
                data_b64: commit_b64.to_string(),
                data_hash: data_hash.to_string(),
            });
            seq
        };
        let _ = seq;
        if let Some(g) = st.groups.get_mut(group_id) {
            g.detail.current_epoch = epoch;
        }
        Ok(())
    }

    fn list_commits_since(&self, group_id: &str, since_epoch: u64) -> Result<Vec<MlsLogRecord>> {
        let st = self.srv.st.lock().unwrap();
        Ok(st
            .logs
            .get(group_id)
            .map(|v| {
                v.iter()
                    // Must match the real server: the SQL is `epoch > ? AND kind <> 'welcome'` (not `kind = 'commit'`);
                    // filtering on "commit" misses "update" (nickname changes), passing tests while the real app fails.
                    .filter(|l| l.kind != "welcome" && l.epoch > since_epoch)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    fn push_welcome(
        &self,
        group_id: &str,
        target_user: &str,
        welcome_b64: &str,
        data_hash: &str,
        epoch: u64,
    ) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        if !st.groups.contains_key(group_id) {
            bail!("group not found");
        }
        // Key point: membership takes effect only when the welcome is stored (matching the real server)
        if let Some(g) = st.groups.get_mut(group_id) {
            if !g.detail.members.iter().any(|m| m.user_id == target_user) {
                g.detail.members.push(MemberInfo {
                    user_id: target_user.to_string(),
                    role: "member".into(),
                    joined_epoch: epoch,
                });
            }
        }
        let logs = st.logs.entry(group_id.to_string()).or_default();
        let seq = logs.len() as u64 + 1;
        logs.push(MlsLogRecord {
            seq,
            epoch,
            kind: "welcome".into(),
            sender: self.user.clone(),
            target: target_user.to_string(),
            data_b64: welcome_b64.to_string(),
            data_hash: data_hash.to_string(),
        });
        Ok(())
    }

    fn list_welcomes(&self, group_id: &str) -> Result<Vec<MlsLogRecord>> {
        let st = self.srv.st.lock().unwrap();
        Ok(st
            .logs
            .get(group_id)
            .map(|v| {
                v.iter()
                    .filter(|l| l.kind == "welcome" && l.target == self.user)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    fn send_group_message(
        &self,
        group_id: &str,
        epoch: u64,
        msg_id: &str,
        ciphertext: &str,
        msg_type: &str,
        file_id: &str,
    ) -> Result<u64> {
        let mut st = self.srv.st.lock().unwrap();
        let g = st.groups.get(group_id).ok_or_else(|| anyhow::anyhow!("group not found"))?;
        if !g.detail.members.iter().any(|m| m.user_id == self.user) {
            bail!("non-members cannot post");
        }
        let seq = {
            let c = st.next_seq.entry(group_id.to_string()).or_insert(0);
            *c += 1;
            *c
        };
        st.messages.entry(group_id.to_string()).or_default().push(GroupMsgRecord {
            seq,
            epoch,
            sender: self.user.clone(),
            msg_id: msg_id.to_string(),
            ciphertext: ciphertext.to_string(),
            msg_type: msg_type.to_string(),
            file_id: file_id.to_string(),
        });
        Ok(seq)
    }

    fn list_messages_since(
        &self,
        group_id: &str,
        since_seq: u64,
        limit: usize,
    ) -> Result<PulledMessages> {
        let st = self.srv.st.lock().unwrap();
        let min_seq = *st.min_seq.get(group_id).unwrap_or(&0);
        let start = since_seq.max(min_seq);
        let mut msgs: Vec<GroupMsgRecord> = st
            .messages
            .get(group_id)
            .map(|v| v.iter().filter(|m| m.seq > start).cloned().collect())
            .unwrap_or_default();
        msgs.sort_by_key(|m| m.seq);
        msgs.truncate(limit);
        // Simulate the server returning "my role in this group" along with the messages
        let my_role = st
            .groups
            .get(group_id)
            .and_then(|g| {
                g.detail
                    .members
                    .iter()
                    .find(|m| m.user_id == self.user)
                    .map(|m| m.role.clone())
            });
        Ok(PulledMessages { messages: msgs, min_seq, my_role })
    }

    fn ack_messages(&self, group_id: &str, last_seq: u64) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let k = (group_id.to_string(), self.user.clone());
        let e = st.cursors.entry(k).or_insert(0);
        *e = (*e).max(last_seq);
        Ok(())
    }

    /// Equivalent to the real `store.LeaveGroup`: atomic, idempotent, and **an owner must name a successor**.
    fn leave_group(&self, group_id: &str, successor: Option<&str>) -> Result<()> {
        // Phase 1: read-only (role, other members, dissolution); borrows end inside the block
        let mut pending_transfer: Option<(String, String)> = None;
        let (my_role, others, dissolved) = {
            let mut st = self.srv.st.lock().unwrap();
            let g = st
                .groups
                .get_mut(group_id)
                .ok_or_else(|| anyhow::anyhow!("GROUP_NOT_FOUND: group not found"))?;
            let Some(role) = g
                .detail
                .members
                .iter()
                .find(|m| m.user_id == self.user)
                .map(|m| m.role.clone())
            else {
                return Ok(()); // idempotent: was not a member anyway
            };
            let others: Vec<String> = g
                .detail
                .members
                .iter()
                .filter(|m| m.user_id != self.user)
                .map(|m| m.user_id.clone())
                .collect();

            let mut dissolved = false;
            if role == "owner" {
                if others.is_empty() {
                    g.state = "dissolved".to_string();
                    dissolved = true;
                } else {
                    let Some(succ) = successor.map(|s| s.trim()).filter(|s| !s.is_empty()) else {
                        bail!("SUCCESSOR_REQUIRED: the owner must designate a new owner before leaving");
                    };
                    if succ == self.user || !others.iter().any(|o| o == succ) {
                        bail!("INVALID_SUCCESSOR: the new owner must be an existing member of this group and cannot be yourself");
                    }
                    // No immediate promotion: register a pending transfer (the group has no owner until then)
                    pending_transfer = Some((succ.to_string(), group_id.to_string()));
                }
            }
            (role, others, dissolved)
        };
        let _ = (my_role, others);

        // Phase 2: update the member table, clear the cursor, register the todo
        let mut st = self.srv.st.lock().unwrap();
        if let Some(g) = st.groups.get_mut(group_id) {
            g.detail.members.retain(|m| m.user_id != self.user);
        }
        st.cursors.remove(&(group_id.to_string(), self.user.clone()));
        if let Some((succ, g2)) = pending_transfer {
            if !st
                .transfers
                .iter()
                .any(|(gg, _, _, s)| gg == &g2 && s == "pending")
            {
                st.transfers.push((g2, self.user.clone(), succ, "pending".to_string()));
            }
        }
        if !dissolved {
            let e = st.pending_removals.entry(group_id.to_string()).or_default();
            if !e.iter().any(|u| u == &self.user) {
                e.push(self.user.clone());
            }
        }
        Ok(())
    }

    fn member_roles(&self, group_id: &str) -> Result<Vec<(String, String)>> {
        let st = self.srv.st.lock().unwrap();
        Ok(st
            .groups
            .get(group_id)
            .map(|g| {
                g.detail
                    .members
                    .iter()
                    .map(|m| (m.user_id.clone(), m.role.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn start_owner_transfer(&self, group_id: &str, designee: &str) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let g = st
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("GROUP_NOT_FOUND: group not found"))?;
        let my_role = g
            .detail
            .members
            .iter()
            .find(|m| m.user_id == self.user)
            .map(|m| m.role.clone())
            .unwrap_or_default();
        if my_role != "owner" {
            anyhow::bail!("NOT_OWNER: only the owner can start a transfer");
        }
        if designee == self.user
            || !g.detail.members.iter().any(|m| m.user_id == designee)
        {
            anyhow::bail!("INVALID_SUCCESSOR: the designee must be an existing member of this group and cannot be yourself");
        }
        if st
            .transfers
            .iter()
            .any(|(gg, _, _, s)| gg == group_id && s == "pending")
        {
            anyhow::bail!("TRANSFER_PENDING: there is already a pending transfer");
        }
        st.transfers.push((
            group_id.to_string(),
            self.user.clone(),
            designee.to_string(),
            "pending".to_string(),
        ));
        Ok(())
    }

    fn pending_owner_transfer(
        &self,
        group_id: &str,
    ) -> Result<Option<crate::group::transport::OwnerTransferInfo>> {
        let st = self.srv.st.lock().unwrap();
        Ok(st
            .transfers
            .iter()
            .find(|(g, _, _, s)| g == group_id && s == "pending")
            .map(|(g, prev, d, s)| crate::group::transport::OwnerTransferInfo {
                group_id: g.clone(),
                prev_owner: prev.clone(),
                designee: d.clone(),
                state: s.clone(),
            }))
    }

    fn decide_owner_transfer(&self, group_id: &str, accept: bool) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let idx = st
            .transfers
            .iter()
            .position(|(g, _, _, s)| g == group_id && s == "pending")
            .ok_or_else(|| anyhow::anyhow!("TRANSFER_NOT_FOUND: no pending transfer"))?;
        let (_g, prev, designee, _) = st.transfers[idx].clone();
        if designee != self.user {
            anyhow::bail!("NOT_DESIGNEE: only the designee can confirm this transfer");
        }
        let new_state = if accept { "accepted" } else { "declined" };
        st.transfers[idx].3 = new_state.to_string();

        let g = st
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("GROUP_NOT_FOUND: group not found"))?;
        if accept {
            for m in g.detail.members.iter_mut() {
                if m.user_id == prev {
                    m.role = "member".to_string();
                }
                if m.user_id == designee {
                    m.role = "owner".to_string();
                }
            }
        } else {
            let owners = g.detail.members.iter().filter(|m| m.role == "owner").count();
            if owners == 0 {
                g.state = "dissolved".to_string();
            }
        }
        Ok(())
    }

    fn list_pending_removals(&self, group_id: &str) -> Result<Vec<String>> {
        let st = self.srv.st.lock().unwrap();
        let g = st
            .groups
            .get(group_id)
            .ok_or_else(|| anyhow::anyhow!("GROUP_NOT_FOUND: group not found"))?;
        let actor = g
            .detail
            .members
            .iter()
            .find(|m| m.user_id == self.user)
            .map(|m| m.role.clone())
            .unwrap_or_default();
        if actor != "owner" && actor != "admin" {
            bail!("FORBIDDEN: only owner/admin can view pending removals");
        }
        Ok(st
            .pending_removals
            .get(group_id)
            .cloned()
            .unwrap_or_default())
    }

    fn clear_pending_removals(&self, group_id: &str) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        st.pending_removals.remove(group_id);
        Ok(())
    }

    /// The stub "kick": mirrors the server — only the owner may delete someone else's member row.
    fn kick_member(&self, group_id: &str, target_user: &str) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let g = st
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("group not found"))?;
        let actor = g
            .detail
            .members
            .iter()
            .find(|m| m.user_id == self.user)
            .map(|m| m.role.clone())
            .unwrap_or_default();
        if actor != "owner" {
            anyhow::bail!("NOT_OWNER: only the owner can remove members");
        }
        if g.detail.creator == target_user {
            anyhow::bail!("NOT_OWNER: the owner cannot be removed");
        }
        g.detail.members.retain(|m| m.user_id != target_user);
        Ok(())
    }

    fn dissolve_group(&self, group_id: &str) -> Result<()> {
        let mut st = self.srv.st.lock().unwrap();
        let g = st.groups.get(group_id).ok_or_else(|| anyhow::anyhow!("group not found"))?;
        if g.detail.creator != self.user {
            bail!("only the owner can dissolve the group");
        }
        st.groups.remove(group_id);
        Ok(())
    }
}

// Public keys per user in the fake server, so search can return creator_public_key
thread_local! {
    static CREATOR_PUBKEYS: Mutex<HashMap<String, String>> = Mutex::new(HashMap::new());
}

fn test_creator_pubkey(user: &str) -> String {
    CREATOR_PUBKEYS.with(|m| m.lock().unwrap().get(user).cloned().unwrap_or_default())
}

// Test scaffolding

struct Party {
    svc: GroupService,
    _store: Arc<Store>,
}

fn party(server: &Arc<FakeServer>, name: &str) -> (Party, rsa::RsaPrivateKey) {
    // One RSA identity per user (the join note is encrypted to the owner with it)
    let (priv_pem, pub_pem) = crate::crypto::generate_keypair().expect("failed to generate RSA");
    let priv_key = crate::crypto::parse_private(&priv_pem).expect("failed to parse the private key");
    let user_id = crate::crypto::public_key_id(&pub_pem, 10).expect("failed to derive the user_id");
    let _ = name;

    CREATOR_PUBKEYS.with(|m| {
        m.lock().unwrap().insert(user_id.clone(), pub_pem.clone());
    });

    let store = Arc::new(Store::open(":memory:", None).expect("failed to create the in-memory database"));
    store
        .insert_server("srv", "test", "127.0.0.1", 1)
        .expect("failed to write the server");
    store
        .upsert_identity(&crate::store::Identity {
            server_id: "srv".into(),
            username: user_id.clone(),
            private_key: priv_pem.clone(),
            public_key: pub_pem.clone(),
        })
        .expect("failed to write the identity");

    let svc = GroupService::new(
        store.clone(),
        Arc::new(server.as_user(&user_id)),
        "srv",
        user_id,
        Arc::new(priv_key.clone()),
    );
    (Party { svc, _store: store }, priv_key)
}

// End-to-end cases

/// Guards the whole flow: create, apply, approve, join, two-way messaging, and key rotation after membership changes.
#[test]
fn group_create_approve_join_send_and_rotate() {
    let server = FakeServer::new();

    let (alice, _a_key) = party(&server, "alice");
    let gid = alice.svc.create_group("Test Group", "me").expect("Alice failed to create the group").group_id;
    assert_eq!(alice.svc.local_groups().unwrap().len(), 1);
    assert_eq!(
        alice.svc.decrypt_group_name(&gid).unwrap().as_deref(),
        Some("Test Group")
    );
    assert!(alice.svc.is_member(&gid).unwrap());

    let (bob, _b_key) = party(&server, "bob");
    let hits = bob.svc.search_group(&gid).expect("search failed");
    assert_eq!(hits.len(), 1, "searching by group ID should find it");
    let pending = bob
        .svc
        .request_join(&gid, "I am Bob, please let me join", "me")
        .expect("join request failed");
    assert!(!bob.svc.is_member(&gid).unwrap(), "not a member yet after requesting");

    let reqs = alice.svc.list_join_requests(&gid).expect("failed to fetch requests");
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].1, "I am Bob, please let me join", "the request text should decrypt");

    let (epoch_after_add, added_user) = alice
        .svc
        .approve_and_add(&gid, &pending.request_id)
        .expect("approve and add failed");
    assert_eq!(epoch_after_add, 1, "epoch 1 should be reached after Add");
    assert_eq!(added_user, reqs[0].0.applicant);
    assert_eq!(alice.svc.remote_members(&gid).unwrap().len(), 2);

    let bob_epoch = bob.svc.complete_join(&gid).expect("Bob failed to join");
    assert_eq!(bob_epoch, 1, "Bob should be at the same epoch as Alice");
    assert!(bob.svc.is_member(&gid).unwrap());
    assert_eq!(bob.svc.local_members(&gid).unwrap().len(), 2);

    alice.svc.send_text(&gid, "hi everyone, I am Alice").expect("Alice failed to send");
    let n = bob.svc.sync_group(&gid).expect("Bob failed to sync");
    assert_eq!(n, 1, "Bob should receive 1 message");
    let msgs = bob.svc.local_messages(&gid, 0).unwrap();
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].plaintext, "hi everyone, I am Alice");

    bob.svc.send_text(&gid, "got it, I am Bob").expect("Bob failed to send");
    alice.svc.sync_group(&gid).expect("Alice failed to sync");
    let amsgs = alice.svc.local_messages(&gid, 0).unwrap();
    assert!(amsgs.iter().any(|m| m.plaintext == "got it, I am Bob"));

    // Key rotation: Alice adds Carol -> epoch 2
    let (carol, _c_key) = party(&server, "carol");
    let cp = carol.svc.request_join(&gid, "I am Carol", "me").expect("Carol failed to request");
    let (_e2, _u) = alice
        .svc
        .approve_and_add(&gid, &cp.request_id)
        .expect("failed to add Carol");
    assert_eq!(alice.svc.local_groups().unwrap()[0].current_epoch, 2, "epoch 2 should be reached");
    let carol_epoch = carol.svc.complete_join(&gid).expect("Carol failed to join");
    assert_eq!(carol_epoch, 2);

    bob.svc.sync_group(&gid).expect("Bob failed to catch up on the epoch");
    assert_eq!(
        bob.svc.local_groups().unwrap()[0].current_epoch,
        2,
        "Bob should advance to epoch 2 via the Commit"
    );

    // Post-rotation messages must use the new epoch key and decrypt for all three
    alice.svc.send_text(&gid, "post-rotation message").expect("send failed");
    for (who, p) in [("bob", &bob), ("carol", &carol)] {
        p.svc.sync_group(&gid).unwrap_or_else(|e| panic!("{who} failed to sync: {e:#}"));
        let ms = p.svc.local_messages(&gid, 0).unwrap();
        assert!(
            ms.iter().any(|m| m.plaintext == "post-rotation message"),
            "{who} should decrypt the post-rotation message"
        );
    }

    // Regression: the group name must stay decryptable across epochs. It used to be encrypted with the epoch-bound
    // `export_secret`, so it broke as soon as membership changed; it now lives in an epoch-constant group context extension (new members get it via Welcome).
    for (who, p) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        assert_eq!(
            p.svc.decrypt_group_name(&gid).unwrap().as_deref(),
            Some("Test Group"),
            "{who} should still decrypt the group name at epoch 2 (the name key is constant across epochs)"
        );
    }

    let cm = carol.svc.local_messages(&gid, 0).unwrap();
    assert!(
        !cm.iter().any(|m| m.plaintext == "hi everyone, I am Alice"),
        "new members must not see pre-join messages"
    );
}

/// Guards that a denied applicant gets no Welcome and cannot join.
#[test]
fn denied_join_request_cannot_join() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Group", "me").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pending = bob.svc.request_join(&gid, "let me in", "me").unwrap();
    alice
        .svc
        .decide_join_request(&gid, &pending.request_id, false)
        .expect("rejection failed");

    assert!(alice.svc.list_join_requests(&gid).unwrap().is_empty());
    assert!(
        bob.svc.complete_join(&gid).is_err(),
        "a rejected request must not be able to join"
    );
}

/// Guards that non-members cannot send and that a duplicate request is rejected.
#[test]
fn non_member_cannot_send_and_duplicate_request_rejected() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Group", "me").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    assert!(
        bob.svc.send_text(&gid, "sneaky message").is_err(),
        "non-members must not be able to send messages"
    );
    bob.svc.request_join(&gid, "first time", "me").unwrap();
    assert!(
        bob.svc.request_join(&gid, "second time", "me").is_err(),
        "the same person must not have two pending requests in one group"
    );
}

/// Guards that only the owner can dissolve, that local data is cleared, and that others are rejected.
#[test]
fn dissolve_group_owner_only_and_clears_local() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Group To Dissolve", "me").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let p = bob.svc.request_join(&gid, "let me in", "me").unwrap();
    alice.svc.approve_and_add(&gid, &p.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    assert!(bob.svc.dissolve_group(&gid).is_err(), "non-owners must not be able to dissolve the group");
    assert!(bob.svc.local_groups().unwrap().iter().any(|g| g.group_id == gid));

    alice.svc.dissolve_group(&gid).unwrap();
    assert!(
        alice.svc.local_groups().unwrap().iter().all(|g| g.group_id != gid),
        "the group must be gone locally after dissolution"
    );
    assert!(alice.svc.local_messages(&gid, 0).unwrap().is_empty());
}

/// Guards the group ID shape: exactly 10 lowercase base36 chars, hand-copyable, pinned here to prevent drift.
#[test]
fn group_id_is_10_char_lowercase_base36() {
    use super::service::{is_valid_group_id, new_group_id, GROUP_ID_LEN};

    assert_eq!(GROUP_ID_LEN, 10);
    for _ in 0..200 {
        let id = new_group_id();
        assert_eq!(id.len(), GROUP_ID_LEN, "length must be 10: {id}");
        assert!(
            id.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()),
            "only digits and lowercase letters allowed: {id}"
        );
        assert!(is_valid_group_id(&id));
    }

    let bad = [
        "0123456789abcdef0123456789abcdef0123456789abcdef", // old 48-char hex
        "abc",
        "a1b2c3d4e5f",
        "A1B2C3D4E5",
        "a1b2c3d4e-",
        "a1b2c3d4e_",
        "",
    ];
    for b in bad {
        assert!(!is_valid_group_id(b), "must not pass validation: {b:?}");
    }

    let set: std::collections::HashSet<String> =
        (0..200).map(|_| new_group_id()).collect();
    assert!(set.len() > 190, "200 generations should be almost unique, got {} distinct", set.len());
}

/// Guards that the nickname travels in the MLS credential: the one set at request time is visible on both sides (so message display names have a source).
/// Nicknames go in the credential rather than the server by design: the server is an opaque forwarder that should neither know nor be able to tamper with them.
#[test]
fn group_nickname_propagates_via_credential() {
    use super::service::{decode_credential, encode_credential, CRED_SEP};

    // Encode/decode must round-trip; the separator is stripped from nicknames (prevents forging a user_id)
    assert_eq!(encode_credential("abc123", "Bob"), format!("abc123{CRED_SEP}Bob"));
    assert_eq!(decode_credential(&format!("abc123{CRED_SEP}Bob")),
               ("abc123".into(), "Bob".into()));
    assert_eq!(encode_credential("abc123", ""), "abc123");
    assert_eq!(decode_credential("abc123"), ("abc123".into(), String::new()));
    // A separator smuggled into a nickname is stripped, so it cannot forge a second user_id
    let evil = format!("x{CRED_SEP}evil");
    assert_eq!(encode_credential("abc123", &evil).matches(CRED_SEP).count(), 1);
    assert_eq!(decode_credential(&encode_credential("abc123", &evil)).0, "abc123");

    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Nickname Group", "Owner Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pending = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pending.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    // Owner's view: Bob's nickname comes from the credential; user_id is public-key-derived hex, so compare against the actual value
    let alice_id = alice.svc.username().to_string();
    let bob_id = bob.svc.username().to_string();
    let am = alice.svc.local_members(&gid).unwrap();
    let bob_row = am.iter().find(|m| m.user_id == bob_id).expect("Bob should be present");
    assert_eq!(bob_row.nickname, "Bob", "the owner should see the applicant's nickname");
    assert_eq!(alice.svc.member_display_name(&gid, &bob_row.user_id), "Bob");

    let bm = bob.svc.local_members(&gid).unwrap();
    let owner = bm.iter().find(|m| m.user_id == alice_id).expect("the owner should be present");
    assert_eq!(owner.nickname, "Owner Alice", "the applicant should see the owner's nickname");

}

/// Guards that the last joiner can see earlier members' nicknames.
/// Carol's Welcome carries the full ratchet tree, so she sees Alice's and Bob's nicknames, and vice versa.
#[test]
fn last_joiner_sees_earlier_members_nicknames() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Three-person Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();

    // In the real app Bob syncs on push; running it explicitly here stands for the background sync after `group_notify`.
    // **Live UI refresh depends on this**: a rename produces no new message, so the background thread can only tell that
    // group state changed from "did the epoch advance". Without an advance the member's group name stays stale until restart.
    let bob_ep_before = bob.svc.local_epoch(&gid);
    bob.svc.sync_group(&gid).expect("Bob failed to sync");
    assert!(
        bob.svc.local_epoch(&gid) > bob_ep_before,
        "after a member syncs the rename commit the local epoch must advance (otherwise the UI will not refresh the group name)"
    );

    let aid = alice.svc.username().to_string();
    let bid = bob.svc.username().to_string();
    let cid = carol.svc.username().to_string();

    let cm = carol.svc.local_members(&gid).unwrap();
    let nick_of = |uid: &str| {
        cm.iter().find(|m| m.user_id == uid).map(|m| m.nickname.clone())
    };
    assert_eq!(nick_of(&aid).as_deref(), Some("Alice"), "Carol should see the owner's nickname");
    assert_eq!(nick_of(&bid).as_deref(), Some("Bob"), "Carol should see the earlier joiner's nickname");
    assert_eq!(nick_of(&cid).as_deref(), Some("Carol"), "Carol should see her own nickname");

    let am = alice.svc.local_members(&gid).unwrap();
    assert_eq!(
        am.iter().find(|m| m.user_id == cid).map(|m| m.nickname.as_str()),
        Some("Carol"),
        "the owner should see the last joiner's nickname"
    );
    let bm = bob.svc.local_members(&gid).unwrap();
    assert_eq!(
        bm.iter().find(|m| m.user_id == cid).map(|m| m.nickname.as_str()),
        Some("Carol"),
        "the earlier joiner should see the last joiner's nickname"
    );
}

/// Guards that `group_kicked_me` recognizes "group alive but I am no longer a member" (NOT_GROUP_MEMBER); treating only dissolution/absence as cleanup would leave a permanently failing zombie group.
#[test]
fn kicked_predicate_distinguishes_removal_from_dissolution() {
    use crate::group::service::{group_is_gone, group_kicked_me};

    let kicked = anyhow::anyhow!("group command failed: NOT_GROUP_MEMBER: not a group member");
    assert!(group_kicked_me(&kicked), "NOT_GROUP_MEMBER should be treated as being removed");
    assert!(!group_is_gone(&kicked), "the group still exists, so it must not be treated as dissolved");

    let dissolved = anyhow::anyhow!("GROUP_DISSOLVED: the group has been dissolved");
    assert!(group_is_gone(&dissolved));
    assert!(!group_kicked_me(&dissolved), "dissolution is not being removed");

    let notfound = anyhow::anyhow!("GROUP_NOT_FOUND: group not found");
    assert!(group_is_gone(&notfound));
    assert!(!group_kicked_me(&notfound));

    let other = anyhow::anyhow!("network timeout");
    assert!(!group_is_gone(&other) && !group_kicked_me(&other));
}

/// Guards that leaving is a real MLS operation: after the Remove is broadcast, no other member's roster still lists the leaver.
/// Regression guard for the "leaving only deletes the server member row" bug, which left the leaver listed and, with no key rotation, still able to decrypt later messages.
#[test]
fn leave_group_removes_me_from_other_members_lists() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Leave Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    let aid = alice.svc.username().to_string();
    let bid = bob.svc.username().to_string();
    alice.svc.sync_group(&gid).unwrap();
    let am = alice.svc.local_members(&gid).unwrap();
    assert!(am.iter().any(|m| m.user_id == bid), "the owner should see Bob before he leaves");

    // Bob leaves: server member row dropped + local cleared (he **cannot** submit the commit that removes himself)
    bob.svc.leave_group(&gid, None).unwrap();
    assert!(bob.svc.local_groups().unwrap().is_empty(), "the leaver's local copy should be cleared immediately");

    // Owner syncs: reconcile sees Bob is off the server roster -> submit Remove -> rotate keys
    alice.svc.sync_group(&gid).unwrap();
    let am = alice.svc.local_members(&gid).unwrap();
    assert!(
        !am.iter().any(|m| m.user_id == bid),
        "the leaver must disappear from other members' rosters, but is still present: {am:?}"
    );
    assert!(am.iter().any(|m| m.user_id == aid), "the owner of course remains");
    assert!(alice.svc.local_groups().unwrap()[0].current_epoch > 1, "leaving should advance the epoch");
}


/// Guards that a join note stays readable by the new owner after a transfer.
/// The note is encrypted to the approver (the current owner), not the creator; encrypting to `creator_public_key` left the new owner seeing "cannot decrypt".
#[test]
fn join_note_stays_readable_by_the_new_owner_after_transfer() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "nt-alice");
    let gid = alice.svc.create_group("Readable Note", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "nt-bob");
    let p = bob.svc.request_join(&gid, "let Bob in", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &p.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // Transfer ownership to Bob and have him confirm -> he becomes the sole owner
    alice.svc.start_owner_transfer(&gid, &bid).unwrap();
    bob.svc.decide_owner_transfer(&gid, true).unwrap();
    bob.svc.sync_group(&gid).unwrap();
    assert_eq!(bob.svc.local_groups().unwrap()[0].my_role.as_str(), "owner");

    // A new request now arrives and only **Bob (the new owner)** can approve it
    let (carol, _) = party(&server, "nt-carol");
    carol
        .svc
        .request_join(&gid, "I am Carol, I want to join", "Carol")
        .unwrap();

    let reqs = bob.svc.list_join_requests(&gid).expect("the new owner should be able to fetch requests");
    assert_eq!(reqs.len(), 1);
    assert_eq!(
        reqs[0].1, "I am Carol, I want to join",
        "the new owner must be able to decrypt the request note -- it is encrypted to the approver (the current owner), not the creator"
    );
    assert!(
        !reqs[0].1.contains("undecryptable"),
        "undecryptable must not appear: {}",
        reqs[0].1
    );

    // Alice the creator is no longer the approver, so failing to decrypt is **expected** (the note goes only to the current owner)
    let old = alice.svc.list_join_requests(&gid);
    if let Ok(rows) = old {
        if let Some((_, txt)) = rows.first() {
            assert!(
                txt.contains("undecryptable") || txt == "I am Carol, I want to join",
                "the creator-side behavior is not strictly constrained, actual: {txt}"
            );
        }
    }
}

/// Guards that everyone's roles update after a transfer: roles are not part of MLS (the ratchet tree has none), so MLS-only
/// member sync would freeze other members' roles at old values and F9 would keep showing the previous owner.
#[test]
fn member_roles_refresh_for_everyone_after_transfer() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "mr-alice");
    let gid = alice.svc.create_group("Role Refresh", "Alice").unwrap().group_id;
    let (bob, _) = party(&server, "mr-bob");
    let (carol, _) = party(&server, "mr-carol");
    for (p, nick) in [(&bob, "Bob"), (&carol, "Carol")] {
        let req = p.svc.request_join(&gid, "please add me", nick).unwrap();
        alice.svc.approve_and_add(&gid, &req.request_id).unwrap();
        p.svc.complete_join(&gid).unwrap();
    }
    let bid = bob.svc.username().to_string();
    let aid = alice.svc.username().to_string();
    let role_of = |c: &Party, uid: &str| {
        c.svc
            .local_members(&gid)
            .unwrap()
            .into_iter()
            .find(|m| m.user_id == uid)
            .map(|m| m.role.as_str().to_string())
            .unwrap_or_default()
    };
    // Sync once first: the roster comes from the ratchet tree plus the server role table
    carol.svc.sync_group(&gid).unwrap();
    assert_eq!(role_of(&carol, &aid), "owner");
    assert_eq!(role_of(&carol, &bid), "member");
    alice.svc.start_owner_transfer(&gid, &bid).unwrap();
    bob.svc.decide_owner_transfer(&gid, true).unwrap();
    carol.svc.sync_group(&gid).unwrap();
    assert_eq!(role_of(&carol, &bid), "owner", "Carol should see Bob become the owner");
    assert_eq!(role_of(&carol, &aid), "member", "Carol should see Alice demoted to member");
}


/// Guards a standalone transfer: until confirmation the previous owner stays owner and joins are not blocked (only queued for approval); after confirmation the roles swap and the previous owner becomes a member.
#[test]
fn pending_transfer_does_not_block_joins_and_keeps_the_owner_in_charge() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Transfer In Progress", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // Owner starts the transfer; the designee has not confirmed yet
    alice.svc.start_owner_transfer(&gid, &bid).unwrap();
    assert!(
        alice.svc.pending_owner_transfer(&gid).unwrap().is_some(),
        "the pending transfer should be visible"
    );
    assert_eq!(
        alice.svc.local_groups().unwrap()[0].my_role.as_str(),
        "owner"
    );

    // **Joins are not blocked**: a third person can still submit a request
    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol");
    assert!(
        pc.is_ok(),
        "joining during a standalone transfer must not be rejected, actual: {:?}",
        pc.err().map(|e| e.to_string())
    );
    let pc = pc.unwrap();
    alice
        .svc
        .approve_and_add(&gid, &pc.request_id)
        .expect("the former owner should still be able to approve before confirmation");
    carol.svc.complete_join(&gid).unwrap();

    // The designee confirms -> roles transfer
    bob.svc.decide_owner_transfer(&gid, true).unwrap();
    bob.svc.sync_group(&gid).unwrap();
    alice.svc.sync_group(&gid).unwrap();
    assert_eq!(bob.svc.local_groups().unwrap()[0].my_role.as_str(), "owner");
    assert_eq!(
        alice.svc.local_groups().unwrap()[0].my_role.as_str(),
        "member",
        "the former owner should be demoted to a regular member"
    );
    assert!(alice.svc.pending_owner_transfer(&gid).unwrap().is_none());
}

/// Guards an owner leaving with a named successor: he exits at once, the group has no owner until the successor
/// confirms, joins are rejected with GROUP_OWNER_UPDATING, and they recover after confirmation.
#[test]
fn leaving_owner_blocks_joins_until_the_successor_confirms() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Pending Takeover", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // The owner names Bob and then **leaves immediately**
    alice.svc.leave_group(&gid, Some(&bid)).unwrap();
    assert!(alice.svc.local_groups().unwrap().is_empty(), "the owner should have left");
    assert!(
        bob.svc.pending_owner_transfer(&gid).unwrap().is_some(),
        "a pending transfer should be left behind"
    );

    let (carol, _) = party(&server, "carol");
    let e = format!(
        "{:#}",
        carol.svc.request_join(&gid, "please add me", "Carol").unwrap_err()
    );
    assert!(
        e.contains("the group owner is being updated"),
        "it should report that the owner is being updated, actual: {e}"
    );

    bob.svc.decide_owner_transfer(&gid, true).unwrap();
    bob.svc.sync_group(&gid).unwrap();
    assert_eq!(bob.svc.local_groups().unwrap()[0].my_role.as_str(), "owner");
    let pc = carol
        .svc
        .request_join(&gid, "please add me", "Carol")
        .expect("joining should work again after confirmation");
    bob.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
}

/// Guards that **rename and kick are owner-only** (admins included in the denial).
#[test]
fn only_the_owner_can_rename_and_kick() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Permissions Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    let cid = carol.svc.username().to_string();

    // Promote Bob to admin by editing the server role directly, standing in for an already-authorized admin
    {
        let mut st = server.st.lock().unwrap();
        let g = st.groups.get_mut(&gid).unwrap();
        for m in g.detail.members.iter_mut() {
            if m.user_id == bid {
                m.role = "admin".to_string();
            }
        }
    }

    let e = bob.svc.set_group_name(&gid, "admin tries to rename").unwrap_err().to_string();
    assert!(e.contains("only the owner can change the group name"), "an admin must not be able to rename the group, actual: {e}");
    let e = bob.svc.remove_member(&gid, &cid).unwrap_err().to_string();
    assert!(e.contains("only the owner can remove members"), "an admin must not be able to kick members, actual: {e}");

    alice.svc.set_group_name(&gid, "Owner Rename").unwrap();
    assert_eq!(
        alice.svc.decrypt_group_name(&gid).unwrap().as_deref(),
        Some("Owner Rename")
    );
    alice.svc.remove_member(&gid, &cid).unwrap();
    assert!(!alice
        .svc
        .local_members(&gid)
        .unwrap()
        .iter()
        .any(|m| m.user_id == cid));

    assert!(bob.svc.remove_member(&gid, &bid).is_err(), "cannot remove yourself");
}


/// Guards that an owner leaving must name a successor: otherwise nobody can push Commits and rename/kick/add/reconcile all break permanently.
#[test]
fn owner_leaving_requires_a_successor_and_transfers_ownership() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Succession Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    let e = alice.svc.leave_group(&gid, None).unwrap_err().to_string();
    assert!(e.contains("must designate"), "it should require designating a new owner, actual: {e}");
    assert!(!alice.svc.local_groups().unwrap().is_empty(), "must not leave after being rejected");

    assert!(alice.svc.leave_group(&gid, Some("nobody")).is_err());
    let aid = alice.svc.username().to_string();
    assert!(alice.svc.leave_group(&gid, Some(&aid)).is_err());

    // Naming Bob lets the owner leave; Bob takes over only after confirming in the approval list
    alice.svc.leave_group(&gid, Some(&bid)).unwrap();
    assert!(alice.svc.local_groups().unwrap().is_empty(), "the owner should have left");
    bob.svc
        .decide_owner_transfer(&gid, true)
        .expect("the successor should be able to accept the transfer");
    bob.svc.sync_group(&gid).unwrap();

    // Bob can now push Commits (kick/rename); add Carol and have Bob kick her to prove he really has the powers
    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    bob.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    let cid = carol.svc.username().to_string();
    bob.svc.remove_member(&gid, &cid).expect("the succeeding owner should be able to kick members");
    assert!(!bob
        .svc
        .local_members(&gid)
        .unwrap()
        .iter()
        .any(|m| m.user_id == cid));
}

/// Guards that an offline owner still catches up on removals: leave notifications are best-effort and not persisted, but the
/// server records the pending removal as a durable todo, so the owner schedules a sync and submits the commit on next start.
#[test]
fn pending_removal_is_picked_up_by_an_offline_owner_on_startup() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Todo Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // Bob leaves (Alice is "offline" right now and plays no part)
    bob.svc.leave_group(&gid, None).unwrap();

    // Alice comes online: the startup re-check sees the todo first (exactly what runtime does)
    assert!(
        alice.svc.has_pending_removals(&gid),
        "the owner should be able to read pending removals for their own group"
    );
    alice.svc.sync_group(&gid).unwrap();
    assert!(
        !alice
            .svc
            .local_members(&gid)
            .unwrap()
            .iter()
            .any(|m| m.user_id == bid),
        "after the owner comes online and syncs, the leaver should be removed from the ratchet tree"
    );
    assert!(
        !alice.svc.has_pending_removals(&gid),
        "the todo should be cleared after the commit is pushed successfully"
    );

    // Non-owners cannot read the todo (the server refuses), which must be treated as "none" rather than an error
    let (dave, _) = party(&server, "dave");
    assert!(!dave.svc.has_pending_removals(&gid));
}

/// Guards that messages keep flowing while the successor is offline: sending needs only membership and a matching epoch, with
/// no role requirement, and succession touches neither epoch, log, nor ratchet tree; only admin operations (approve/rename/kick/reconcile) freeze.
#[test]
fn messages_keep_flowing_while_the_new_owner_is_offline() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Successor Offline", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // Everyone catches up; after this **Bob is fully offline** (not a single sync)
    bob.svc.sync_group(&gid).unwrap();
    carol.svc.sync_group(&gid).unwrap();
    let epoch_before = carol.svc.local_groups().unwrap()[0].current_epoch;

    // The owner hands ownership to the **offline** Bob, then leaves
    alice.svc.leave_group(&gid, Some(&bid)).unwrap();

    // 1. Messages flow normally (one before and one after the commit, covering the whole "succession done, removal pending" window)
    carol.svc
        .send_text(&gid, "can send while the new owner is offline")
        .expect("members should still be able to send while the successor is offline");
    let msgs = carol.svc.local_messages(&gid, 0).unwrap();
    assert!(
        msgs.iter().any(|m| m.plaintext == "can send while the new owner is offline"),
        "the local side should encrypt and persist normally"
    );

    // 2. The epoch must not change meanwhile: succession itself produces no Commit
    assert_eq!(
        carol.svc.local_groups().unwrap()[0].current_epoch,
        epoch_before,
        "succession is server-side role bookkeeping and must not advance the epoch"
    );

    // 3. Bob comes online: **accepts** the transfer in the approval list, then submits the "remove A" commit
    bob.svc
        .decide_owner_transfer(&gid, true)
        .expect("the successor should be able to accept the transfer");
    bob.svc.sync_group(&gid).expect("the new owner should be able to sync after coming online");
    let epoch_after = bob.svc.local_groups().unwrap()[0].current_epoch;
    assert!(
        epoch_after > epoch_before,
        "after the new owner comes online the removal commit should be submitted and the epoch advanced ({epoch_before} -> {epoch_after})"
    );
    let aid = alice.svc.username().to_string();
    assert!(
        !bob.svc
            .local_members(&gid)
            .unwrap()
            .iter()
            .any(|m| m.user_id == aid),
        "the former owner should be removed from the ratchet tree"
    );

    // 4. After another member syncs: the old owner is gone and **window-period messages remain readable**
    carol.svc.sync_group(&gid).unwrap();
    assert!(
        !carol
            .svc
            .local_members(&gid)
            .unwrap()
            .iter()
            .any(|m| m.user_id == aid),
        "the former owner should be removed from every member's roster"
    );
    let msgs = carol.svc.local_messages(&gid, 0).unwrap();
    assert!(
        msgs.iter().any(|m| m.plaintext == "can send while the new owner is offline"),
        "after crossing the removal commit, messages from the transition window should still be readable locally"
    );
    carol.svc.send_text(&gid, "business as usual after rotation").unwrap();
    bob.svc.sync_group(&gid).unwrap();
    assert!(
        bob.svc
            .local_messages(&gid, 0)
            .unwrap()
            .iter()
            .any(|m| m.plaintext == "business as usual after rotation"),
        "the new owner should decrypt post-rotation messages"
    );
}

/// Guards the transition window: messages sent between a leaver leaving and the owner submitting the Remove must stay
/// decryptable for offline members, since sync merges Commits before pulling messages and openmls' default `MaxEpochs(0)` keeps no past-epoch keys (`adapter::MAX_PAST_EPOCHS` exists for this).
#[test]
fn messages_sent_before_a_removal_commit_stay_decryptable_for_offline_members() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Transition Window", "Alice").unwrap().group_id;

    // Bob and Carol join
    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    // Carol catches up first, then **goes offline** (no more syncs)
    carol.svc.sync_group(&gid).unwrap();
    let epoch_before = carol.svc.local_groups().unwrap()[0].current_epoch;

    // Bob syncs to the latest epoch first (the real server requires sender epoch == group epoch)
    bob.svc.sync_group(&gid).unwrap();
    let bob_epoch = bob.svc.local_groups().unwrap()[0].current_epoch;
    bob.svc.send_text(&gid, "words spoken before leaving").unwrap();

    // Bob leaves; the owner (the only online admin) reconciles and submits the Remove -> epoch advances
    bob.svc.leave_group(&gid, None).unwrap();
    alice.svc.sync_group(&gid).unwrap();
    let epoch_after = alice.svc.local_groups().unwrap()[0].current_epoch;
    assert!(
        epoch_after > epoch_before,
        "the removal commit should advance the epoch ({epoch_before} -> {epoch_after})"
    );

    // Only now does Carol come online: sync **merges the commit first** (jumping to epoch_after) and **pulls messages afterwards**
    carol.svc.sync_group(&gid).unwrap();

    let msgs = carol.svc.local_messages(&gid, 0).unwrap();
    let got = msgs.iter().find(|m| m.plaintext == "words spoken before leaving");
    assert!(
        got.is_some(),
        "messages sent during the transition window must still be decryptable; actual messages: {:?}",
        msgs.iter().map(|m| (m.seq, m.epoch, m.plaintext.clone())).collect::<Vec<_>>()
    );
    let cm = carol.svc.local_members(&gid).unwrap();
    assert!(
        !cm.iter().any(|m| m.user_id == bid),
        "after Carol syncs, the departed Bob should no longer be in the roster"
    );
}

/// Guards **owner kick**: the target can no longer decrypt new messages, and their own client notices the removal.
#[test]
fn owner_removes_member_and_target_notices() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Kick Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();
    let bid = bob.svc.username().to_string();

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    assert!(
        carol.svc.remove_member(&gid, &bid).is_err(),
        "a regular member cannot remove others"
    );

    let aid = alice.svc.username().to_string();
    assert!(alice.svc.remove_member(&gid, &aid).is_err(), "removing members must not be used to leave the group");

    let ep = alice.svc.remove_member(&gid, &bid).unwrap();
    assert!(ep > 1, "removing a member should advance the epoch");
    let am = alice.svc.local_members(&gid).unwrap();
    assert!(!am.iter().any(|m| m.user_id == bid), "Bob should no longer be in the owner's roster");

    carol.svc.sync_group(&gid).unwrap();
    let cm = carol.svc.local_members(&gid).unwrap();
    assert!(!cm.iter().any(|m| m.user_id == bid), "Bob should no longer be in other members' rosters");

    // When Bob syncs he must **discover the removal** and clear his local copy
    let r = bob.svc.sync_group(&gid);
    assert!(r.is_err(), "a removed member should get a clear error when syncing");
    assert!(
        r.unwrap_err().to_string().contains("removed"),
        "the error message should say the member was removed"
    );
    assert!(
        bob.svc.local_groups().unwrap().is_empty(),
        "the removed member's local copy should be cleared, leaving no zombie group"
    );
}

/// Guards rename: one GroupContextExtensions commit applies group-wide and later joiners get it from the Welcome.
/// Three things: the initiator sees the new name immediately, existing members after merging the Commit, and members joining after the rename get it from the Welcome.
#[test]
fn group_rename_propagates_and_new_joiners_see_it() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");
    let gid = alice.svc.create_group("Old Group Name", "Alice").unwrap().group_id;

    // Bob joins first (before the rename)
    let (bob, _) = party(&server, "bob");
    let pb = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &pb.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    assert_eq!(alice.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("Old Group Name"));
    assert_eq!(bob.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("Old Group Name"));

    // 1. The owner renames
    let ep_before = alice.svc.local_groups().unwrap()[0].current_epoch;
    let ep_after = alice.svc.set_group_name(&gid, "New Group Name").unwrap();
    assert!(ep_after > ep_before, "a rename is a Commit, so the epoch should advance");
    assert_eq!(
        alice.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("New Group Name"),
        "the initiator should see the new group name immediately"
    );

    bob.svc.sync_group(&gid).expect("Bob failed to sync");
    assert_eq!(
        bob.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("New Group Name"),
        "existing members should see the new group name after merging the Commit"
    );

    let (carol, _) = party(&server, "carol");
    let pc = carol.svc.request_join(&gid, "please add me", "Carol").unwrap();
    alice.svc.approve_and_add(&gid, &pc.request_id).unwrap();
    carol.svc.complete_join(&gid).unwrap();
    assert_eq!(
        carol.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("New Group Name"),
        "a joiner after the rename should get the new group name from the Welcome's group context"
    );

    // Empty name / over-long name / non-admin
    assert!(alice.svc.set_group_name(&gid, "   ").is_err(), "an empty group name should be rejected");
    assert!(alice.svc.set_group_name(&gid, &"x".repeat(65)).is_err(), "an over-long group name should be rejected");
    assert!(bob.svc.set_group_name(&gid, "I want to rename too").is_err(), "non-admins cannot rename the group");
    assert_eq!(alice.svc.decrypt_group_name(&gid).unwrap().as_deref(), Some("New Group Name"));
}

/// Guards that nicknames are fixed at creation/request time and cannot be changed later (that would need an Update Commit
/// broadcast to the whole group, a path that has been removed). Two things: nicknames are required, and they land correctly via the credential.
#[test]
fn nickname_is_fixed_at_join_time() {
    let server = FakeServer::new();
    let (alice, _) = party(&server, "alice");

    // Nickname is required when creating a group
    assert!(alice.svc.create_group("x", "  ").is_err(), "the creation nickname is required");
    let gid = alice.svc.create_group("Naming Group", "Alice").unwrap().group_id;

    let (bob, _) = party(&server, "bob");
    assert!(bob.svc.request_join(&gid, "please add me", "").is_err(), "the request nickname is required");
    assert!(bob.svc.request_join(&gid, "  ", "Bob").is_err(), "the request note is required");

    let p = bob.svc.request_join(&gid, "please add me", "Bob").unwrap();
    alice.svc.approve_and_add(&gid, &p.request_id).unwrap();
    bob.svc.complete_join(&gid).unwrap();

    let aid = alice.svc.username().to_string();
    let bid = bob.svc.username().to_string();
    let am = alice.svc.local_members(&gid).unwrap();
    assert_eq!(am.iter().find(|m| m.user_id == aid).unwrap().nickname, "Alice");
    assert_eq!(am.iter().find(|m| m.user_id == bid).unwrap().nickname, "Bob");
    let bm = bob.svc.local_members(&gid).unwrap();
    assert_eq!(bm.iter().find(|m| m.user_id == aid).unwrap().nickname, "Alice");
}
