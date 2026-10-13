//! Pure group data structures (serializable, no openmls types).
//! Keeps opaque MLS private state (from `adapter`) separate from business metadata (used by UI/sync).

use serde::{Deserialize, Serialize};

/// Role within a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupRole {
    Owner,
    Admin,
    Member,
}

impl GroupRole {
    pub fn as_str(self) -> &'static str {
        match self {
            GroupRole::Owner => "owner",
            GroupRole::Admin => "admin",
            GroupRole::Member => "member",
        }
    }

    /// Whether this role may send MLS Add/Remove commits.
    pub fn can_commit(self) -> bool {
        matches!(self, GroupRole::Owner | GroupRole::Admin)
    }
}

impl std::str::FromStr for GroupRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(GroupRole::Owner),
            "admin" => Ok(GroupRole::Admin),
            "member" => Ok(GroupRole::Member),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

/// Local business state for one group; MLS private material lives separately in `mls_private_state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupState {
    /// Group ID: 10 chars of lowercase base36, generated locally by the creator.
    pub group_id: String,
    /// Group name ciphertext (encrypted with the group key, unreadable by the server).
    pub name_enc: Vec<u8>,
    /// My role in the group.
    pub my_role: GroupRole,
    /// MLS epoch we have synced to.
    pub current_epoch: u64,
    /// Epoch I joined at; earlier messages are out of reach due to MLS forward secrecy.
    pub joined_epoch: u64,
    /// Deleted lower bound of the group queue (server-side `groups.min_seq`).
    pub min_seq: u64,
    /// Local ack position in the group queue.
    pub last_seq: u64,
}

impl GroupState {
    /// Whether this epoch is decryptable. Pre-join epochs are reported as undecryptable rather
    /// than as an error, since MLS forward secrecy makes them unrecoverable anyway.
    pub fn can_decrypt_epoch(&self, epoch: u64) -> bool {
        epoch >= self.joined_epoch && epoch <= self.current_epoch
    }

    /// Whether we are behind the server's visible lower bound, i.e. messages were dropped.
    pub fn is_truncated(&self) -> bool {
        self.min_seq > self.last_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(joined: u64, cur: u64, min_seq: u64, last_seq: u64) -> GroupState {
        GroupState {
            group_id: "g".into(),
            name_enc: vec![],
            my_role: GroupRole::Member,
            current_epoch: cur,
            joined_epoch: joined,
            min_seq,
            last_seq,
        }
    }

    /// Guards the decrypt window: join epoch through current epoch, nothing outside.
    #[test]
    fn decrypt_window_respects_join_epoch() {
        let s = st(3, 7, 0, 0);
        assert!(!s.can_decrypt_epoch(2), "epochs before joining are undecryptable");
        assert!(s.can_decrypt_epoch(3), "the join epoch is decryptable");
        assert!(s.can_decrypt_epoch(7), "the current epoch is decryptable");
        assert!(!s.can_decrypt_epoch(8), "future epochs are undecryptable (must catch up on the Commit first)");
    }

    /// Guards truncation detection when the server's `min_seq` passes our ack point.
    #[test]
    fn truncation_detected() {
        assert!(!st(0, 5, 10, 10).is_truncated());
        assert!(st(0, 5, 11, 10).is_truncated(), "min_seq greater than last_seq means truncated");
    }

    /// Guards that only owner/admin may commit.
    #[test]
    fn role_commit_permission() {
        assert!(GroupRole::Owner.can_commit());
        assert!(GroupRole::Admin.can_commit());
        assert!(!GroupRole::Member.can_commit());
    }

    /// Guards role string round-trip and rejection of unknown roles.
    #[test]
    fn role_roundtrip() {
        for r in [GroupRole::Owner, GroupRole::Admin, GroupRole::Member] {
            assert_eq!(r.as_str().parse::<GroupRole>().unwrap(), r);
        }
        assert!("bogus".parse::<GroupRole>().is_err());
    }
}
