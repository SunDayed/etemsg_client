//! Server-interaction abstraction for the group protocol.
//! The trait keeps `service` orchestration off the network so end-to-end tests can use a fake; the real REST implementation lives in the net layer.

use anyhow::Result;

/// Create-group request / response.
#[derive(Debug, Clone)]
pub struct CreateGroupReq {
    pub group_id: String,
    pub name_enc: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct CreateGroupResp {
    pub group_id: String,
}

/// Group detail (member roster).
#[derive(Debug, Clone)]
pub struct GroupDetail {
    pub group_id: String,
    pub name_enc: Option<Vec<u8>>,
    pub creator: String,
    pub current_epoch: u64,
    pub min_seq: u64,
    pub members: Vec<MemberInfo>,
}

#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub user_id: String,
    pub role: String,
    pub joined_epoch: u64,
}

/// Search hit; search is by group ID only.
#[derive(Debug, Clone)]
pub struct GroupSearchHit {
    pub group_id: String,
    pub name_enc: Option<Vec<u8>>,
    pub creator: String,
    /// Creator public key, locally checked against `public_key_id(pub) == creator`.
    pub creator_public_key: String,
    /// Current owner (= approver, differs from `creator` after a transfer; empty when unknown or the group has no owner).
    pub owner: String,
    /// Current owner's public key, locally checked against `public_key_id(pub) == owner`.
    pub owner_public_key: String,
    pub member_count: u64,
}

/// Join request as seen by the server; the note text is ciphertext addressed to the owner.
#[derive(Debug, Clone)]
pub struct JoinRequestRecord {
    pub request_id: String,
    pub group_id: String,
    pub applicant: String,
    pub kp_id: String,
    pub kp_hash: String,
    pub text_ct: String,
    pub text_iv: String,
    pub text_tag: String,
    pub text_wrapped_key: String,
    pub status: String,
}

/// Control-log entry (both Commits and Welcomes).
#[derive(Debug, Clone)]
pub struct MlsLogRecord {
    pub seq: u64,
    pub epoch: u64,
    pub kind: String,
    pub sender: String,
    pub target: String,
    pub data_b64: String,
    pub data_hash: String,
}

/// Group message entry.
#[derive(Debug, Clone)]
pub struct GroupMsgRecord {
    pub seq: u64,
    pub epoch: u64,
    pub sender: String,
    pub msg_id: String,
    pub ciphertext: String,
    pub msg_type: String,
    pub file_id: String,
}

/// Pending owner transfer.
#[derive(Debug, Clone, Default)]
pub struct OwnerTransferInfo {
    pub group_id: String,
    pub prev_owner: String,
    pub designee: String,
    pub state: String,
}

/// Result of pulling group messages: the messages plus the server's deletion lower bound.
#[derive(Debug, Clone)]
pub struct PulledMessages {
    /// My role as reported by the server; owner succession can happen while I am offline, so
    /// piggybacking it on the pull saves a round trip.
    pub my_role: Option<String>,
    pub messages: Vec<GroupMsgRecord>,
    pub min_seq: u64,
}

/// Server interaction for groups. Every method assumes the request is already signed.
#[allow(clippy::too_many_arguments)]
pub trait GroupTransport {
    // Group lifecycle
    fn create_group(&self, req: &CreateGroupReq) -> Result<CreateGroupResp>;
    fn get_group(&self, group_id: &str) -> Result<GroupDetail>;
    fn search_by_id(&self, group_id: &str) -> Result<Vec<GroupSearchHit>>;

    fn upload_key_package(
        &self,
        group_id: &str,
        kp_id: &str,
        kp_b64: &str,
        kp_hash: &str,
    ) -> Result<()>;
    fn fetch_key_package(&self, group_id: &str, kp_id: &str) -> Result<String>;
    /// Submit a join request.
    fn submit_join_request(&self, req: &JoinRequestRecord) -> Result<()>;
    fn list_join_requests(&self, group_id: &str) -> Result<Vec<JoinRequestRecord>>;
    fn decide_join_request(
        &self,
        group_id: &str,
        request_id: &str,
        allow: bool,
    ) -> Result<()>;

    fn push_commit(
        &self,
        group_id: &str,
        epoch: u64,
        parent_epoch: u64,
        kind: &str,
        commit_b64: &str,
        data_hash: &str,
    ) -> Result<()>;
    fn list_commits_since(&self, group_id: &str, since_epoch: u64) -> Result<Vec<MlsLogRecord>>;
    fn push_welcome(
        &self,
        group_id: &str,
        target_user: &str,
        welcome_b64: &str,
        data_hash: &str,
        epoch: u64,
    ) -> Result<()>;
    fn list_welcomes(&self, group_id: &str) -> Result<Vec<MlsLogRecord>>;

    fn send_group_message(
        &self,
        group_id: &str,
        epoch: u64,
        msg_id: &str,
        ciphertext: &str,
        msg_type: &str,
        file_id: &str,
    ) -> Result<u64>;
    fn list_messages_since(
        &self,
        group_id: &str,
        since_seq: u64,
        limit: usize,
    ) -> Result<PulledMessages>;
    fn ack_messages(&self, group_id: &str, last_seq: u64) -> Result<()>;

    // Members and lifecycle
    /// Leave the group; an owner with remaining members must pass `successor` (else `SUCCESSOR_REQUIRED`).
    fn leave_group(&self, group_id: &str, successor: Option<&str>) -> Result<()>;

    /// List members who lost access but are still in the MLS tree (owner/admin only).
    /// The server only records the todo; a client must submit the Remove commit once the owner is back online (the server does not parse MLS).
    fn list_pending_removals(&self, group_id: &str) -> Result<Vec<String>>;

    /// Clear the group's pending removals (call after the Remove commit has been pushed).
    fn clear_pending_removals(&self, group_id: &str) -> Result<()>;
    /// Fetch the server's authoritative `(user_id, role)` table.
    /// The MLS ratchet tree carries no roles, so MLS-only member sync leaves other members' roles stale — hence F9 showed the old owner after a transfer.
    fn member_roles(&self, group_id: &str) -> Result<Vec<(String, String)>>;

    /// Owner starts a transfer: name a successor and wait for them to confirm.
    fn start_owner_transfer(&self, group_id: &str, designee: &str) -> Result<()>;

    /// View the pending transfer (visible to the designee and the current owner).
    fn pending_owner_transfer(&self, group_id: &str) -> Result<Option<OwnerTransferInfo>>;

    /// Designee accepts or declines the transfer.
    fn decide_owner_transfer(&self, group_id: &str, accept: bool) -> Result<()>;

    /// Owner removes a member: drops that member's row on the server.
    /// Order matters — the MLS Remove commit must be pushed first, while we are still a member.
    fn kick_member(&self, group_id: &str, target_user: &str) -> Result<()>;
    /// Dissolve the group (owner only). The server sets `state='dissolved'` and the group becomes unusable.
    fn dissolve_group(&self, group_id: &str) -> Result<()>;
}
