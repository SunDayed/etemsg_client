//! Wires the group service into a running client.
//!
//! [`GroupService`] is built on demand (not resident, avoiding a strong reference cycle with `Core`). The WS thread only marks groups dirty; a background thread pulls and decrypts serially — the WS thread must never do network I/O or decryption, or it stalls heartbeats and 1v1 delivery.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};

use super::net_transport::CoreTransport;
use super::service::GroupService;
use crate::core::Core;
use crate::store::Store;

/// Group runtime state (hung off `Core`).
#[derive(Default)]
pub struct GroupRuntime {
    pending: Mutex<HashSet<(String, String)>>,
    /// Groups with a pending join request (server push `group_notify reason=join_request`)
    approvals: Mutex<HashSet<(String, String)>>,
    started: Mutex<HashSet<String>>,
    /// Whether the one-shot startup approval re-check has already run (see the worker loop)
    checked_approvals: std::sync::atomic::AtomicBool,
}

impl GroupRuntime {
    /// Mark a group as needing sync (called on WS push; **performs no I/O**).
    pub fn mark(&self, sid: &str, gid: &str) {
        self.pending
            .lock()
            .unwrap()
            .insert((sid.to_string(), gid.to_string()));
    }

    /// Mark a group as having pending join requests (only owner/admin receive this push).
    pub fn mark_approval(&self, sid: &str, gid: &str) {
        self.approvals
            .lock()
            .unwrap()
            .insert((sid.to_string(), gid.to_string()));
    }

    /// Take and clear the set of groups awaiting sync.
    pub fn drain(&self) -> Vec<(String, String)> {
        let mut g = self.pending.lock().unwrap();
        g.drain().collect()
    }

    /// Take and clear the set of groups with approvals to surface.
    pub fn drain_approvals(&self) -> Vec<(String, String)> {
        let mut g = self.approvals.lock().unwrap();
        g.drain().collect()
    }

    /// Whether a sync thread has already been started for this server.
    fn claim_start(&self, sid: &str) -> bool {
        self.started.lock().unwrap().insert(sid.to_string())
    }

    /// Whether this call owns the startup approval re-check (only the first caller wins).
    fn claim_approval_check(&self) -> bool {
        !self
            .checked_approvals
            .swap(true, std::sync::atomic::Ordering::SeqCst)
    }
}

/// Build a `GroupService` for one server (on demand, not cached); requires a login, since both `username` and the private key come from the local identity.
pub fn service_for(core: &Arc<Core>, sid: &str) -> Result<GroupService> {
    let transport = CoreTransport::new(core.clone(), sid)?;
    let username = core
        .username_of(sid)
        .context("not logged in, group features are unavailable")?;
    let priv_key = core.priv_key(sid).context("missing the local private key")?;
    Ok(GroupService::new(
        core.store.clone(),
        Arc::new(transport),
        sid,
        username,
        priv_key,
    ))
}

/// Start the background sync thread (one per server, idempotent): periodic `sync_group`, emitting `Event::GroupDirty` on changes.
/// A fixed-interval poll rather than a condition variable also absorbs lost WS pushes (group pushes are best-effort; pulls are authoritative).
pub fn start_worker(core: &Arc<Core>, sid: &str) {
    let Some(sess) = core.session(sid) else { return };
    if !sess.group_runtime.claim_start(sid) {
        return;
    }
    let core2 = core.clone();
    let sid2 = sid.to_string();
    std::thread::Builder::new()
        .name(format!("group-sync-{sid}"))
        .spawn(move || {
            while !core2.is_shutting_down() {
                std::thread::sleep(Duration::from_millis(400));
                // Do nothing while logged out (building the service would fail)
                if core2.username_of(&sid2).is_none() {
                    continue;
                }
                let Ok(svc) = service_for(&core2, &sid2) else { continue };

                // Startup re-check: `pending_approvals` is filled only by live pushes and is lost on restart,
                // so on first run re-check the groups I manage, otherwise the F7 text and tree marks disappear.
                let do_check = core2
                    .session(&sid2)
                    .map(|s| s.group_runtime.claim_approval_check())
                    .unwrap_or(false);
                if do_check {
                    let all = svc.local_groups().unwrap_or_default();

                    // Queue every local group for one sync at startup, which also settles three offline cases:
                    // refreshing my role, reconciling departed/removed members (needs the role first), and catching up missed messages. Pushes are best-effort and not persisted, so they alone would miss these.
                    for g in &all {
                        if let Some(ss) = core2.session(&sid2) {
                            ss.group_runtime.mark(&sid2, &g.group_id);
                        }
                    }

                    let owned: Vec<_> = all
                        .into_iter()
                        .filter(|g| g.my_role.can_commit())
                        .collect();
                    crate::tui_log!("startup re-check of pending approvals: I manage {} groups", owned.len());
                    for g in owned {
                        let reqs = match svc.list_join_requests(&g.group_id) {
                            Ok(r) => r,
                            Err(e) => {
                                crate::tui_log!("startup re-check failed group={}: {e:#}", g.group_id);
                                continue;
                            }
                        };
                        if !reqs.is_empty() {
                            crate::tui_log!("startup re-check group={} has {} pending approvals", g.group_id, reqs.len());
                        }
                        // Also re-check pending removals: leave pushes are best-effort but the todo is persisted,
                        // so reading it at startup schedules a sync that later submits the Remove.
                        if svc.has_pending_removals(&g.group_id) {
                            crate::tui_log!(
                                "startup re-check group={} has pending removals, scheduling a sync",
                                g.group_id
                            );
                            if let Some(ss) = core2.session(&sid2) {
                                ss.group_runtime.mark(&sid2, &g.group_id);
                            }
                        }
                        core2.emit(crate::core::Event::GroupPendingApprovals {
                            server_id: sid2.clone(),
                            group_id: g.group_id.clone(),
                            count: reqs.len(),
                        });
                    }
                }

                let (syncs, approvals) = match core2.session(&sid2) {
                    Some(s) => (s.group_runtime.drain(), s.group_runtime.drain_approvals()),
                    None => (Vec::new(), Vec::new()),
                };

                // Owner/admin: someone is waiting for approval
                for (s, gid) in approvals {
                    if s != sid2 {
                        continue;
                    }
                    // Check for a transfer awaiting my confirmation first: the designee is usually a plain member,
                    // so `list_join_requests` fails with FORBIDDEN, and a bare `continue` would leave F7 unmarked forever.
                    let transfer_mine = svc
                        .pending_owner_transfer(&gid)
                        .ok()
                        .flatten()
                        .map(|t| {
                            core2.username_of(&sid2).as_deref() == Some(t.designee.as_str())
                        })
                        .unwrap_or(false);
                    // Only owner/admin can list requests; a failure means I lack permission
                    let reqs = match svc.list_join_requests(&gid) {
                        Ok(r) => r,
                        Err(e) => {
                            if transfer_mine {
                                core2.emit(crate::core::Event::GroupPendingApprovals {
                                    server_id: sid2.clone(),
                                    group_id: gid.clone(),
                                    count: 1,
                                });
                                core2.emit(crate::core::Event::GroupDirty {
                                    server_id: sid2.clone(),
                                    group_id: gid.clone(),
                                });
                                core2.emit(crate::core::Event::Toast(
                                    "an ownership transfer is waiting for your confirmation, press F7".to_string(),
                                ));
                            }
                            crate::tui_log!("pending-approval reminder: fetch failed group={gid}: {e:#}");
                            continue;
                        }
                    };
                    let pending = reqs.len() + usize::from(transfer_mine);
                    crate::tui_log!("pending-approval reminder group={gid} has {} entries (transfer included: {transfer_mine})", reqs.len());
                    if pending == 0 {
                        continue;
                    }
                    let name = svc
                        .decrypt_group_name(&gid)
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| gid.clone());
                    core2.emit(crate::core::Event::Toast(if transfer_mine {
                        format!("group \"{name}\" has an ownership transfer waiting for your confirmation, press F7")
                    } else {
                        format!("group \"{name}\" has {} pending join requests, press F7 to review", reqs.len())
                    }));
                    // Mark it persistently on the session tree (toasts expire, so approvals cannot rely on them)
                    core2.emit(crate::core::Event::GroupPendingApprovals {
                        server_id: sid2.clone(),
                        group_id: gid.clone(),
                        count: reqs.len(),
                    });
                    // Refresh the list too (the group may only appear on the session tree after the notice)
                    core2.emit(crate::core::Event::GroupDirty {
                        server_id: sid2.clone(),
                        group_id: gid.clone(),
                    });
                }

                for (s, gid) in syncs {
                    if s != sid2 {
                        continue;
                    }
                    // Auto-join: once approved the Welcome is available, so consume it without a keypress.
                    let mut joined = false;
                    if !svc.is_member(&gid).unwrap_or(false) {
                        match svc.complete_join(&gid) {
                            Ok(epoch) => {
                                joined = true;
                                crate::tui_log!("auto-joined group={gid} epoch={epoch}");
                            }
                            // No Welcome yet (e.g. this was only a message push) -> skip silently
                            Err(_) => {}
                        }
                    }

                    // Record the epoch first: rename/add/kick are MLS commits that produce **no new messages**,
                    // so judging by "n > 0" alone would leave the group name stale until restart.
                    let epoch_before = svc.local_epoch(&gid);
                    match svc.sync_group(&gid) {
                        Ok(n) => {
                            let group_changed = svc.local_epoch(&gid) != epoch_before;
                            if joined || n > 0 || group_changed {
                                core2.emit(crate::core::Event::GroupDirty {
                                    server_id: sid2.clone(),
                                    group_id: gid.clone(),
                                });
                            }
                        }
                        Err(e) => {
                            // Sync failures are logged, not surfaced -- except when the group is dissolved or I was removed:
                            // `sync_group` drops the local copy, so `GroupDirty` must be emitted or the tree keeps an unopenable zombie.
                            if crate::group::service::group_is_gone(&e)
                                || crate::group::service::group_kicked_me(&e)
                            {
                                crate::tui_log!("group is gone, cleaning up locally and refreshing the UI group={gid}: {e:#}");
                                core2.emit(crate::core::Event::SystemNotice(format!(
                                    "group {gid} is gone: {e}"
                                )));
                                core2.emit(crate::core::Event::GroupDirty {
                                    server_id: sid2.clone(),
                                    group_id: gid.clone(),
                                });
                            } else {
                                crate::tui_log!("group sync failed group={gid}: {e:#}");
                            }
                        }
                    }
                }
            }
        })
        .ok();
}

/// Sync every group I belong to once (manual CLI/UI refresh); returns `(group_id, newly added count)`.
pub fn sync_all(core: &Arc<Core>, sid: &str) -> Result<Vec<(String, usize)>> {
    let svc = service_for(core, sid)?;
    let groups = svc.local_groups()?;
    let mut out = Vec::new();
    for g in groups {
        // A join-only record has no MLS state, so syncing always fails; still verify the group exists
        // (a dissolved owner leaves a stale record that cannot be cleared and keeps showing in the session tree).
        if !svc.is_member(&g.group_id).unwrap_or(false) {
            if svc.group_exists(&g.group_id).unwrap_or(true) == false {
                crate::tui_log!("group {} no longer exists (the join request was not approved), clearing the local record", g.group_id);
                let _ = svc.forget_group(&g.group_id);
            }
            continue;
        }
        match svc.sync_group(&g.group_id) {
            Ok(n) => out.push((g.group_id.clone(), n)),
            // A dissolved group has already been removed locally inside sync_group; nothing to do here
            Err(e) => crate::tui_log!("group sync failed group={}: {e:#}", g.group_id),
        }
    }
    Ok(out)
}

/// Wait for login to complete (used by the CLI).
pub fn wait_login(core: &Arc<Core>, sid: &str, timeout: Duration) -> Result<String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Some(u) = core.username_of(sid) {
            return Ok(u);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("login timed out ({}s)", timeout.as_secs())
}

/// Take the first server id (used when the CLI omits `--server`, matching the other diagnostic modes).
pub fn first_server(store: &Store) -> Result<String> {
    let servers = store.get_servers()?;
    servers
        .first()
        .map(|s| s.id.clone())
        .context("no server in the local database")
}
