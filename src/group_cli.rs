//! Group chat CLI entry point (DB path and master key as in the other diagnostic modes: `--db` / `--key`).
//! **The command must be argv[1]**: anywhere else it is taken for an unknown argument and the TUI starts.
//! Usage: `msg-client-rust <--group-*> [--server <sid>] --db <db> --key <k> [args...]`; see `--help` for the subcommand list.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use msg_client_rust::core::Core;
use msg_client_rust::group::runtime;
use msg_client_rust::group::service::GroupService;
use msg_client_rust::store::Store;

/// Max wait for login; error out instead of hanging the CLI forever.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(20);

struct Ctx {
    core: Arc<Core>,
    sid: String,
    username: String,
}

fn setup(db: &str, key: &str, server: Option<&str>) -> Result<Ctx> {
    let store = Arc::new(Store::open(db, Some(key))?);
    let sid = match server {
        Some(s) => s.to_string(),
        None => runtime::first_server(&store)?,
    };
    let (core, _rx) = Core::new(store)?;
    // trigger login: group REST calls need this machine's username and private key
    core.connect_one(sid.clone());
    let username = runtime::wait_login(&core, &sid, LOGIN_TIMEOUT)?;
    // after login, start the background sync worker (it pulls and decrypts on WS group pushes)
    runtime::start_worker(&core, &sid);
    Ok(Ctx { core, sid, username })
}

impl Ctx {
    fn svc(&self) -> Result<GroupService> {
        runtime::service_for(&self.core, &self.sid)
    }
}

/// Collect positional args, skipping `--` options and their values.
fn positional(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--db" || a == "--key" || a == "--server" {
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            i += 1;
            continue;
        }
        out.push(a.clone());
        i += 1;
    }
    out
}

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

/// Main group command entry point; returns the process exit code.
pub fn run(cmd: &str, args: &[String]) -> i32 {
    let (db, key) = match resolve_db_key(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("group command failed: {e}");
            return 2;
        }
    };
    // watch is a resident command and handles its own exit
    if cmd == "--group-watch" {
        let code = match inner(cmd, &db, &key, args) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("group command failed: {e:#}");
                1
            }
        };
        return code;
    }
    // Other commands: write the WAL back before exiting — the process ends with process::exit while background threads hold Arc<Store>, so SQLite never checkpoints and a copy of etemsg.db alone would be empty.
    let code = match inner(cmd, &db, &key, args) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("group command failed: {e:#}");
            1
        }
    };
    if let Ok(st) = Store::open(&db, Some(&key)) {
        let _ = st.checkpoint();
    }
    code
}

fn resolve_db_key(args: &[String]) -> Result<(String, String)> {
    let db = opt(args, "--db").unwrap_or_else(|| {
        // same lookup order as the TUI: --db > MSG_CLIENT_DB > etemsg.db next to the executable
        std::env::var("MSG_CLIENT_DB").unwrap_or_else(|_| {
            let mut p = std::env::current_exe().unwrap_or_else(|_| ".".into());
            p.pop();
            p.push("etemsg.db");
            p.to_string_lossy().to_string()
        })
    });
    let key = opt(args, "--key")
        .or_else(|| std::env::var("MSG_CLIENT_KEY").ok())
        .filter(|k| !k.is_empty())
        .context("missing master key: provide it with `--key <password>` or the MSG_CLIENT_KEY environment variable")?;
    Ok((db, key))
}

fn inner(cmd: &str, db: &str, key: &str, args: &[String]) -> Result<()> {
    let pos = positional(args);
    // positional[0] is the command itself (argv[1]); placed anywhere else it is treated as an unknown argument and the TUI starts.
    let rest: Vec<&String> = pos.iter().skip(1).collect();

    // watch is a resident command: no positional args needed
    if cmd == "--group-watch" {
        let ctx = setup(db, key, opt(args, "--server").as_deref())?;
        return watch(&ctx);
    }

    let ctx = setup(db, key, opt(args, "--server").as_deref())?;
    let svc = ctx.svc()?;

    match cmd {
        "--group-list" => {
            let groups = svc.local_groups()?;
            if groups.is_empty() {
                println!("(no local groups)");
            }
            for g in groups {
                let name = svc
                    .decrypt_group_name(&g.group_id)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "<cannot decrypt>".into());
                let member = if svc.is_member(&g.group_id).unwrap_or(false) {
                    "joined"
                } else {
                    "requested"
                };
                let unread = ctx
                    .core
                    .store
                    .group_unread(&ctx.sid, &g.group_id)
                    .unwrap_or(0);
                println!(
                    "{}  {}  role={:?}  epoch={}  {}{}",
                    g.group_id,
                    name,
                    g.my_role,
                    g.current_epoch,
                    member,
                    if unread > 0 { format!("  unread={unread}") } else { String::new() }
                );
            }
            Ok(())
        }

        "--group-create" => {
            let name = rest.first().context("usage: --group-create \"group name\" \"my nickname\"")?;
            let nick = rest
                .get(1)
                .context("missing in-group nickname (required): --group-create \"group name\" \"my nickname\"")?;
            let st = svc.create_group(name, nick)?;
            println!("group created");
            println!("  group_id = {}", st.group_id);
            println!("  epoch    = {}", st.current_epoch);
            println!("\nGive the group_id to the other side and have them run:");
            println!("  --group-request {} \"join note\"", st.group_id);
            Ok(())
        }

        "--group-search" => {
            let gid = rest.first().context("usage: --group-search <group_id>")?;
            let hits = svc.search_group(gid)?;
            if hits.is_empty() {
                println!("group not found");
            }
            for h in hits {
                println!(
                    "{}  owner={}  members={}",
                    h.group_id, h.creator, h.member_count
                );
            }
            Ok(())
        }

        "--group-request" => {
            let gid = rest
                .first()
                .context("usage: --group-request <group_id> \"join note\" \"my nickname\"")?;
            let text = rest.get(1).context("missing join note (required)")?;
            let nick = rest.get(2).context("missing in-group nickname (required)")?;
            let p = svc.request_join(gid, text, nick)?;
            println!("join request submitted");
            println!("  request_id = {}", p.request_id);
            println!("\nWaiting for the owner to approve; once approved you join automatically, no further command is needed.");
            Ok(())
        }

        "--group-requests" => {
            let gid = rest.first().context("usage: --group-requests <group_id>")?;
            let reqs = svc.list_join_requests(gid)?;
            if reqs.is_empty() {
                println!("(no pending requests)");
            }
            for (r, text) in reqs {
                // The applicant is not a member yet, so their nickname is only in the uploaded KeyPackage credential; read it so the owner can see who is asking
                let who = svc
                    .applicant_nickname(gid, &r.kp_id)
                    .map(|n| format!("{n} <{}>", r.applicant))
                    .unwrap_or_else(|| r.applicant.clone());
                println!("request_id = {}", r.request_id);
                println!("  applicant = {who}");
                println!("  note      = {text}");
                println!("  approve   = --group-approve {gid} {}", r.request_id);
            }
            Ok(())
        }

        "--group-approve" | "--group-deny" => {
            let allow = cmd == "--group-approve";
            let gid = rest.first().context("usage: <--group-approve|--group-deny> <group_id> <request_id>")?;
            let rid = rest.get(1).context("missing request_id")?;
            if allow {
                let (epoch, user) = svc.approve_and_add(gid, rid)?;
                println!("approved and added: {user}");
                println!("  epoch = {epoch} (keys rotated)");
                println!("\nThe other side can now run: --group-join {gid}");
            } else {
                svc.decide_join_request(gid, rid, false)?;
                println!("request rejected");
            }
            Ok(())
        }

        "--group-dissolve" => {
            let gid = rest.first().context("usage: --group-dissolve <group_id> (owner only)")?;
            svc.dissolve_group(gid)?;
            println!("group {gid} dissolved (local data cleared)");
            Ok(())
        }


        "--group-forget" => {
            // Local records only, never notifying the server; cleans up leftovers for groups the server no longer has, or whose ID format is obsolete
            let gid = rest.first().context("usage: --group-forget <group_id>")?;
            svc.forget_group(gid)?;
            println!("local records cleared: {gid} (the server was not notified)");
            Ok(())
        }

        "--group-rename" => {
            let gid = rest.first().context("usage: --group-rename <group_id> \"new name\"")?;
            let name = rest.get(1).context("missing new group name")?;
            let ep = svc.set_group_name(gid, name)?;
            println!("group renamed to '{name}' (epoch {ep}, broadcast to the whole group)");
            Ok(())
        }

        "--group-transfer" => {
            let gid = rest.first().context("usage: --group-transfer <group_id> <new owner user_id>")?;
            let designee = rest.get(1).context("missing the transferee user_id")?;
            svc.start_owner_transfer(gid, designee)?;
            println!("ownership transfer to {designee} started; waiting for them to confirm in the request list");
            Ok(())
        }

        "--group-transfer-accept" | "--group-transfer-decline" => {
            let cmd = cmd.to_string();
            let gid = rest.first().context("usage: --group-transfer-accept <group_id>")?;
            let accept = cmd == "--group-transfer-accept";
            svc.decide_owner_transfer(gid, accept)?;
            if accept {
                println!("ownership transfer accepted, you are now the owner");
            } else {
                println!("ownership transfer declined");
            }
            Ok(())
        }

        "--group-leave" => {
            let gid = rest.first().context(
                "usage: --group-leave <group_id> [new owner user_id] (required when the owner leaves)",
            )?;
            let successor = rest.get(1).map(|s| s.as_str());
            svc.leave_group(gid, successor)?;
            match successor {
                Some(s) => println!("left the group; ownership transferred to {s}"),
                None => println!("left the group"),
            }
            Ok(())
        }

        "--group-kick" => {
            let gid = rest
                .first()
                .context("usage: --group-kick <group_id> <user_id to remove>")?;
            let target = rest.get(1).context("missing the user_id to remove")?;
            let ep = svc.remove_member(gid, target)?;
            println!("removed {target} (epoch {ep}, keys rotated)");
            Ok(())
        }

        "--group-join" => {
            let gid = rest.first().context("usage: --group-join <group_id>")?;
            let epoch = svc.complete_join(gid)?;
            println!("joined the group, epoch = {epoch}");
            println!("(messages from before joining are not visible by design)");
            Ok(())
        }

        "--group-send" => {
            let gid = rest.first().context("usage: --group-send <group_id> \"text\"")?;
            let text = rest.get(1).context("missing message text")?;
            let seq = svc.send_text(gid, text)?;
            println!("sent (seq={seq}, encrypted with MLS)");
            Ok(())
        }

        "--group-messages" => {
            let gid = rest.first().context("usage: --group-messages <group_id>")?;
            let msgs = svc.local_messages(gid, 0)?;
            if msgs.is_empty() {
                println!("(no local messages for this group; run --group-sync first)");
            }
            for m in msgs {
                let who = if m.sender == ctx.username { "me" } else { &m.sender };
                match m.state.as_str() {
                    "gap" => println!("[{:>4}] {who}: <message from before joining, cannot decrypt>", m.seq),
                    _ => println!("[{:>4}] {who}: {}", m.seq, m.plaintext),
                }
            }
            Ok(())
        }

        "--group-members" => {
            let gid = rest.first().context("usage: --group-members <group_id>")?;
            // The local member table comes from the MLS ratchet tree (the cryptographic authority); roles live only on the server — the tree does not carry them
            for m in svc.local_members(gid)? {
                let who = if m.user_id == ctx.username {
                    format!("{} (me)", m.user_id)
                } else {
                    m.user_id.clone()
                };
                let nick = if m.nickname.is_empty() {
                    "-".to_string()
                } else {
                    m.nickname.clone()
                };
                println!(
                    "{who}  nickname={nick}  role={:?}  joined_epoch={}",
                    m.role, m.joined_epoch
                );
            }
            Ok(())
        }

        "--group-sync" => {
            match rest.first() {
                Some(gid) => {
                    let n = svc.sync_group(gid)?;
                    println!("synced: {n} new");
                }
                None => {
                    let r = runtime::sync_all(&ctx.core, &ctx.sid)?;
                    for (g, n) in r {
                        println!("{g}: {n} new");
                    }
                }
            }
            Ok(())
        }

        other => anyhow::bail!("unknown group command: {other} (see --help)"),
    }
}

/// Resident listener: a background thread pulls and decrypts on WS pushes, while this function polls and prints new messages.
fn watch(ctx: &Ctx) -> Result<()> {
    println!("listening for group messages (Ctrl-C to quit)…  identity = {}", ctx.username);
    let svc = ctx.svc()?;
    let groups = svc.local_groups()?;
    let mut seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for g in &groups {
        seen.insert(g.group_id.clone(), 0);
    }

    // Drain anything queued before startup once; after that the background worker is push-driven.
    // A slow 5-second full-sync fallback covers lost pushes/reconnects without hammering RSA-signed REST.
    let mut last_full_sync = Instant::now() - Duration::from_secs(5);
    loop {
        if last_full_sync.elapsed() >= Duration::from_secs(5) {
            let _ = runtime::sync_all(&ctx.core, &ctx.sid);
            last_full_sync = Instant::now();
        }
        for g in &groups {
            let Ok(msgs) = svc.local_messages(&g.group_id, 0) else { continue };
            let last = *seen.entry(g.group_id.clone()).or_insert(0);
            for m in msgs.iter().filter(|m| m.seq > last) {
                let who = if m.sender == ctx.username { "me" } else { &m.sender };
                let body = if m.state == "gap" {
                    "<message from before joining>".to_string()
                } else {
                    m.plaintext.clone()
                };
                println!("[{} #{}] {who}: {body}", g.group_id, m.seq);
                seen.insert(g.group_id.clone(), m.seq);
            }
        }
        std::thread::sleep(Duration::from_millis(500));
        if ctx.core.is_shutting_down() {
            return Ok(());
        }
    }
}
