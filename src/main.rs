use msg_client_rust::{crypto, net, store, ui};
use msg_client_rust::core::Core;
use msg_client_rust::store::Store;
use std::sync::Arc;

mod group_cli;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args.get(1).map(|s| s.as_str()) {
        Some("--selftest") => selftest(&args),
        Some("--nettest") => nettest(&args),
        Some("--wstest") => wstest(&args),
        Some("--keytest") => { keytest(); return; }
        // group subcommands (see src/group_cli.rs)
        Some(c) if c.starts_with("--group-") => group_cli::run(c, &args),
        // test/deploy bootstrap only: create an identity and optionally one contact
        Some("--bootstrap") => bootstrap(&args),
        // `--help` / `-h`: no master key needed, print usage and exit
        Some("--help") | Some("-h") => { print_usage(); return; }
        _ => match run_tui(&args) {
            Ok(()) => return,
            Err(e) => {
                eprintln!("startup failed: {e:#}");
                1
            }
        },
    };
    std::process::exit(code);
}

fn print_usage() {
    println!("msg-client-rust — end-to-end encrypted chat client (no initialization needed at compile time)\n");
    println!("Usage:");
    println!("  msg-client-rust                        start the TUI");
    println!("  msg-client-rust --db <path>            database path (default: etemsg.db next to the executable)");
    println!("  msg-client-rust --key <pass>           supply the master key directly (skips the interactive prompt; visible in the process list)");
    println!("  msg-client-rust --selftest <db> <key>  open the DB and verify identity derivation / chat_key format");
    println!("  msg-client-rust --nettest  <db> <key>  TLS fingerprint pinning + challenge login");
    println!("  msg-client-rust --wstest   <db> <key>  WS handshake auth + send an encrypted signed message");
    println!("  msg-client-rust --keytest              print crossterm key codes and exit");
    println!("\nThe following subcommands are **development/troubleshooting helpers** (the product is the TUI):");
    println!("  --selftest / --nettest / --wstest / --keytest");
    println!("  --bootstrap <db> <key> <host> <port> [name] [peer_id] [nickname]\n");
    println!("Groups (require --db and --key):");
    println!("  --server <sid>                         select the server (default: the first one)");
    println!("  --group-list / --group-search <gid>");
    println!("  --group-create \"name\" \"my nickname\"   create a group (nickname required; travels with the MLS credential)");
    println!("  --group-request <gid> \"note\" \"nickname\" request to join a group (both note and nickname required)");
    println!("  --group-requests <gid>                 pending requests (includes the applicant's nickname)");
    println!("  --group-approve <gid> <rid> / --group-deny <gid> <rid>");
    println!("  --group-join <gid>                     manually consume a Welcome (joining is automatic; this is a fallback)");
    println!("  --group-leave <gid> [new owner id]     leave the group (an owner must name a successor)");
    println!("  --group-rename <gid> \"new name\"        rename the group (owner only)");
    println!("  --group-kick <gid> <user_id>           remove a member (owner only)");
    println!("  --group-send <gid> \"text\" / --group-messages <gid> / --group-members <gid>");
    println!("  --group-sync [<gid>] / --group-watch");
    println!("  --group-dissolve <gid>                 dissolve the group (owner only)");
    println!("  --group-forget <gid>                   drop local records only (the server is not notified)\n");
    println!("Note: the master key is supplied only at runtime (--key / MSG_CLIENT_KEY / interactive prompt),");
    println!("      and the binary embeds no passphrase, database or initialization state.");
}


/// DB location order (**no DB is embedded in the source**; the dist copy is runtime state): `--db` > `MSG_CLIENT_DB` >
/// etemsg.db next to the executable > etemsg.db in the cwd, creating one if none exists. Opening a DB only runs `CREATE TABLE IF NOT EXISTS` and **never deletes data**.
fn resolve_db(args: &[String]) -> String {
    if let Some(p) = arg_value(args, "--db").or_else(|| std::env::var("MSG_CLIENT_DB").ok()) {
        return p;
    }
    let exe_dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));
    let mut cands: Vec<std::path::PathBuf> = Vec::new();
    if let Some(d) = &exe_dir {
        cands.push(d.join("etemsg.db"));
    }
    cands.push("etemsg.db".into());
    for c in &cands {
        if c.exists() {
            return c.to_string_lossy().to_string();
        }
    }
    match &exe_dir {
        Some(d) => d.join("etemsg.db").to_string_lossy().to_string(),
        None => "etemsg.db".to_string(),
    }
}

/// Default entry point: set a master key (no DB yet) or log in (DB exists), then open SQLCipher and start the TUI. The master key comes **only from runtime**; the binary embeds no passphrase.
fn run_tui(args: &[String]) -> anyhow::Result<()> {
    let db = resolve_db(args);
    let mut key = arg_value(args, "--key").or_else(|| std::env::var("MSG_CLIENT_KEY").ok());
    // Runtime diagnostics must go to a file: once ratatui owns the screen, stderr corrupts the UI.
    match msg_client_rust::log::init() {
        Ok(p) => msg_client_rust::tui_log!("using database: {db} (log: {})", p.display()),
        Err(e) => eprintln!("[msg-client-rust] cannot create log file: {e}"),
    }
    // Whether a DB already exists decides the prompt: exists → enter the master key to log in; missing → set a new master key.
    let db_exists = std::path::Path::new(&db).exists();
    let confirm = !db_exists;

    let mut terminal = ratatui::init();
    let result = (|| -> anyhow::Result<()> {
        let mut last_err: Option<String> = None;
        loop {
            if key.is_none() {
                // confirm=true only occurs when the DB file is missing (first run)
                let note = if confirm {
                    "first run: set the local database master key (\u{2265}6 characters, kept in memory only)"
                } else { "" };
                let title = if confirm { " Set Master Key " } else { " Log In " };
                match ui::prompt_master_key(&mut terminal, title, note, confirm,
                                            last_err.as_deref())? {
                    Some(k) => key = Some(k),
                    None => return Ok(()),
                }
            }
            let k = key.clone().unwrap();
            match Store::open(&db, Some(&k)) {
                Ok(st) => {
                    // SQLCipher creates the DB file on first write; no marker file is needed
                    let (core, rx) = Core::new(Arc::new(st))?;
                    let ui = ui::Ui::new(core.store.clone(), core.clone(), rx);
                    return ui.run(&mut terminal);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let low = msg.to_lowercase();
                    last_err = Some(if low.contains("not a database") || low.contains("hmac") {
                        "login failed: wrong master key (password), please try again.".into()
                    } else {
                        format!("login failed: cannot open database: {msg}")
                    });
                    key = None;
                }
            }
        }
    })();
    ratatui::restore();
    result
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

/// Bootstrap mode (test/deploy): create a server + identity in the given DB, optionally adding one contact.
/// Usage: --bootstrap <db> <key> <host> <port> [server_name] [peer_id] [nickname]; flow: generate RSA-4096 → `POST /register` → write DB → `/add_contact` (fetch + verify key) → write contacts.
fn bootstrap(args: &[String]) -> i32 {
    match bootstrap_inner(args) {
        Ok(()) => 0,
        Err(e) => { eprintln!("bootstrap failed: {e:#}"); 1 }
    }
}

fn bootstrap_inner(args: &[String]) -> anyhow::Result<()> {
    use anyhow::Context;
    let db = args.get(2).context("missing <db>")?;
    let key = args.get(3).context("missing <key>")?;
    let host = args.get(4).context("missing <host>")?;
    let port: u16 = args.get(5).context("missing <port>")?.parse().context("invalid port")?;
    let server_name = args.get(6).cloned().unwrap_or_else(|| format!("{host}:{port}"));
    let peer = args.get(7).cloned();
    let nickname = args.get(8).cloned();

    let st = store::Store::open(db, Some(key))?;
    let sid = format!("{:08x}", crypto::chrono_now_ms() as u64 & 0xffff_ffff);

    // Reuse an existing server row/identity: re-running bootstrap must not mint a second identity, or contacts would point at a discarded key.
    let existing_sid = st.get_servers()?.into_iter().next().map(|s| s.id);
    let (sid, priv_pem, username) = match existing_sid {
        Some(sid) => {
            let uname = st.get_state(&format!("current_user_{sid}"))?
                .context("existing server but missing current_user")?;
            let ident = st.get_identity(&sid, &uname)?.context("existing server but missing identity")?;
            println!("reuse identity={uname}");
            (sid, ident.private_key, uname)
        }
        None => {
            st.insert_server(&sid, &server_name, host, port as i64)?;
            let (priv_pem, pub_pem) = crypto::generate_keypair()?;
            let username = crypto::public_key_id(&pub_pem, 10)?;
            let cfg = net::tls::client_config(None);
            let mut conn = net::http::HttpsConn::connect(host, port, cfg,
                std::time::Duration::from_secs(15))?;
            let (_, reg) = conn.request_json("POST", "/register", host, port,
                Some(&serde_json::json!({"user_id": username, "public_key": pub_pem})))?;
            if reg.get("status").and_then(|v| v.as_str()) != Some("ok") {
                anyhow::bail!("register failed: {}", reg.pointer("/error/message")
                    .and_then(|v| v.as_str()).unwrap_or("unknown error"));
            }
            st.upsert_identity(&store::Identity {
                server_id: sid.clone(), username: username.clone(),
                private_key: priv_pem.clone(), public_key: pub_pem.clone(),
            })?;
            st.set_state(&format!("current_user_{sid}"), &username)?;
            println!("identity={username}");
            (sid, priv_pem, username)
        }
    };

    // optional: add a contact, fetching the server's authoritative key and checking it against the ID
    if let Some(peer_id) = peer {
        let priv_key = crypto::parse_private(&priv_pem)?;
        let signed = crypto::signed_request_body_with_key(
            &priv_key, &[username.clone(), peer_id.clone()])?;
        let mut body = serde_json::json!({"user_id": username, "contact_user_id": peer_id});
        if let (Some(o), Some(sg)) = (body.as_object_mut(), signed.as_object()) {
            for (k, v) in sg { o.insert(k.clone(), v.clone()); }
        }
        let mut conn2 = net::http::HttpsConn::connect(host, port, net::tls::client_config(None),
            std::time::Duration::from_secs(15))?;
        let (_, res) = conn2.request_json("POST", "/add_contact", host, port, Some(&body))?;
        if res.get("status").and_then(|v| v.as_str()) == Some("error") {
            anyhow::bail!("add_contact failed: {}", res.pointer("/error/message")
                .and_then(|v| v.as_str()).unwrap_or("unknown error"));
        }
        let pk = res.pointer("/payload/public_key").and_then(|v| v.as_str())
            .context("server did not return a public key")?;
        if crypto::public_key_id(pk, 10)? != peer_id {
            anyhow::bail!("public key does not match the ID");
        }
        st.set_contact_public_key(&sid, &peer_id, pk)?;
        if let Some(n) = nickname.filter(|n| !n.trim().is_empty()) {
            st.set_contact_nickname(&sid, &peer_id, n.trim())?;
        }
        println!("contact={peer_id}");
    }
    println!("sid={sid}");
    Ok(())
}

/// Resolve DB path + master key for the diagnostic modes; key order `--key` / `MSG_CLIENT_KEY` / third positional arg, with **no built-in default passphrase**.
fn resolve_diag_db_key(args: &[String]) -> Result<(String, String), String> {
    // A positional db must beat the "default" DB: `--selftest <db> <key>` is positional, but `resolve_db` only checks `--db`/the
    // env var and otherwise falls back to the executable's etemsg.db — so the check would inspect a **different file** and its verdict would be worthless.
    let db = if arg_value(args, "--db").is_some()
        || std::env::var("MSG_CLIENT_DB").is_ok()
    {
        resolve_db(args)
    } else {
        args.get(2).cloned().unwrap_or_else(|| resolve_db(args))
    };
    let key = arg_value(args, "--key")
        .or_else(|| std::env::var("MSG_CLIENT_KEY").ok())
        .or_else(|| args.get(3).cloned())
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            "no master key. Provide one with `--key <password>` or the `MSG_CLIENT_KEY` environment variable \
             (diagnostic mode no longer carries a built-in default passphrase).".to_string()
        })?;
    Ok((db, key))
}

/// Selftest: open the local SQLCipher DB and verify identity derivation consistency.
fn selftest(args: &[String]) -> i32 {
    let (db, key) = match resolve_diag_db_key(args) {
        Ok(v) => v,
        Err(e) => { eprintln!("selftest failed: {e}"); return 2; }
    };
    match selftest_inner(&db, &key) {
        Ok(()) => 0,
        Err(e) => { eprintln!("selftest failed: {e:#}"); 1 }
    }
}

fn selftest_inner(db: &str, key: &str) -> anyhow::Result<()> {
    let st = store::Store::open(db, Some(key))?;
    let servers = st.get_servers()?;
    println!("== SQLCipher opened successfully (Rust + rusqlite) ==");
    println!("servers: {}", servers.len());
    for s in &servers {
        let pin = st.get_cert_pin(&s.id)?.map(|p| format!("{}…", &p[..16])).unwrap_or("-".into());
        println!("  {} {}:{}  pin={}", s.name, s.host, s.api_port, pin);
        let contacts = st.get_contacts(&s.id)?;
        let me = st.get_state(&format!("current_user_{}", s.id))?;
        println!("    current_user = {:?}", me);
        if let Some(u) = me {
            if let Some(ident) = st.get_identity(&s.id, &u)? {
                let derived = crypto::public_key_id(&ident.public_key, 10)?;
                let ok = derived == ident.username;
                println!("    identity {} -> sha512(SPKI)[:10]={}  {}", ident.username, derived,
                         if ok { "✅ match" } else { "❌ mismatch" });
                crypto::parse_private(&ident.private_key)?;
                println!("    private key parsed OK ({} bytes PEM)", ident.private_key.len());
            }
        }
        for c in contacts.iter().filter(|c| c.deleted == 0) {
            println!("    contact {}  pubkey={}", c.username,
                     c.public_key.as_ref().map(|p| format!("{}B", p.len())).unwrap_or("none".into()));
            if let Some(pk) = &c.public_key {
                println!("      -> sha512(SPKI)[:10] = {}", crypto::public_key_id(pk, 10)?);
            }
        }
    }
    // verify chat_key formatting against Python json.dumps
    let ck = store::make_chat_key("801ec47b5c", "a5112fd8ec");
    println!("\nchat_key example: {}", ck);
    assert_eq!(ck, r#"["801ec47b5c", "a5112fd8ec"]"#, "chat_key format must match Python json.dumps");
    println!("chat_key format check ✅");
    Ok(())
}


/// Network selftest against a real server: TLS pinning + challenge-signature login.
fn nettest(args: &[String]) -> i32 {
    let (db, key) = match resolve_diag_db_key(args) {
        Ok(v) => v,
        Err(e) => { eprintln!("network selftest failed: {e}"); return 2; }
    };
    match nettest_inner(&db, &key) {
        Ok(()) => 0,
        Err(e) => { eprintln!("network selftest failed: {e:#}"); 1 }
    }
}

fn nettest_inner(db: &str, key: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    let st = store::Store::open(db, Some(key))?;
    let servers = st.get_servers()?;
    let srv = servers.first().context("no server in the database")?;
    let user = st.get_state(&format!("current_user_{}", srv.id))?
        .context("no current user in the database")?;
    let ident = st.get_identity(&srv.id, &user)?.context("no identity in the database")?;

    println!("target server  : {} {}:{}", srv.name, srv.host, srv.api_port);
    println!("local identity : {}", ident.username);

    // TLS + SPKI pinning
    let saved = st.get_cert_pin(&srv.id)?;
    let saved_for_cb = saved.clone();
    let pin_log = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let pin_log2 = pin_log.clone();
    let check: net::tls::PinCheck = std::sync::Arc::new(move |pin: &str| {
        *pin_log2.lock().unwrap() = Some(pin.to_string());
        match &saved_for_cb {
            None => Ok(()),                       // TOFU: accept on first sight
            Some(s) if s == pin => Ok(()),        // matches
            Some(s) => Err(format!("certificate fingerprint changed: expected {s} actual {pin}")),
        }
    });
    let cfg = net::tls::client_config(Some(check));
    let mut conn = net::http::HttpsConn::connect(
        &srv.host, srv.api_port as u16, cfg, std::time::Duration::from_secs(10))?;
    let (status, body) = conn.request_json(
        "POST", "/login/challenge", &srv.host, srv.api_port as u16,
        Some(&serde_json::json!({"user_id": ident.username})))?;
    let real_pin = pin_log.lock().unwrap().clone().unwrap_or_default();
    println!("TLS handshake OK, SPKI fingerprint = {}", real_pin);
    println!("  matches the fingerprint recorded in the DB : {}", saved.as_deref() == Some(real_pin.as_str()));
    if saved.is_none() { st.set_cert_pin(&srv.id, &real_pin)?; println!("  (fingerprint recorded per TOFU)"); }

    // challenge-signature login
    println!("\n/login/challenge -> HTTP {}  {}", status, serde_json::to_string(&body)?);
    let challenge = body.get("payload").and_then(|p| p.get("challenge"))
        .and_then(|c| c.as_str()).context("no challenge in the response")?.to_string();
    let digest = crypto::md5_hex(&challenge);
    let signature = crypto::sign_message(&ident.private_key, &digest)?;
    let mut conn2 = net::http::HttpsConn::connect(
        &srv.host, srv.api_port as u16, net::tls::client_config(None),
        std::time::Duration::from_secs(10))?;
    let (st2, body2) = conn2.request_json(
        "POST", "/login", &srv.host, srv.api_port as u16,
        Some(&serde_json::json!({"user_id": ident.username, "signature": signature})))?;
    println!("/login           -> HTTP {}", st2);
    let ok = body2.get("status").and_then(|v| v.as_str()) == Some("ok");
    let token = body2.get("payload").and_then(|p| p.get("token")).and_then(|t| t.as_str()).unwrap_or("");
    let contacts = body2.get("payload").and_then(|p| p.get("contacts")).and_then(|c| c.as_array()).map(|a| a.len()).unwrap_or(0);
    println!("  login result = {}   token length = {}   server-side contacts = {}", ok, token.len(), contacts);
    if ok {
        st.set_token(&srv.id, token)?;
        println!("  ✅ challenge login succeeded (the server accepted the Rust md5+PKCS1v15 signature)");
    } else {
        println!("  ❌ login failed: {}", serde_json::to_string(&body2)?);
    }
    Ok(())
}


/// WebSocket selftest: connect → send an encrypted+signed message → wait for the server ack.
fn wstest(args: &[String]) -> i32 {
    let (db, key) = match resolve_diag_db_key(args) {
        Ok(v) => v,
        Err(e) => { eprintln!("WS selftest failed: {e}"); return 2; }
    };
    match wstest_inner(&db, &key) {
        Ok(()) => 0,
        Err(e) => { eprintln!("WS selftest failed: {e:#}"); 1 }
    }
}

fn wstest_inner(db: &str, key: &str) -> anyhow::Result<()> {
    use anyhow::Context;
    let st = store::Store::open(db, Some(key))?;
    let srv = st.get_servers()?.into_iter().next().context("no server")?;
    let me = st.get_state(&format!("current_user_{}", srv.id))?.context("no identity")?;
    let ident = st.get_identity(&srv.id, &me)?.context("missing identity record")?;
    let contacts: Vec<_> = st.get_contacts(&srv.id)?.into_iter().filter(|c| c.deleted == 0).collect();
    let contact = contacts.first().context("no contact")?;
    let peer_pub = contact.public_key.clone().context("contact has no public key")?;

    let mut hc = net::http::HttpsConn::connect(&srv.host, srv.api_port as u16,
        net::tls::client_config(None), std::time::Duration::from_secs(10))?;
    let (_, ch) = hc.request_json("POST", "/login/challenge", &srv.host, srv.api_port as u16,
        Some(&serde_json::json!({"user_id": ident.username})))?;
    let challenge = ch.pointer("/payload/challenge").and_then(|v| v.as_str()).context("no challenge")?;
    let sig = crypto::sign_message(&ident.private_key, &crypto::md5_hex(challenge))?;
    let mut hc2 = net::http::HttpsConn::connect(&srv.host, srv.api_port as u16,
        net::tls::client_config(None), std::time::Duration::from_secs(10))?;
    let (_, login) = hc2.request_json("POST", "/login", &srv.host, srv.api_port as u16,
        Some(&serde_json::json!({"user_id": ident.username, "signature": sig})))?;
    let token = login.pointer("/payload/token").and_then(|v| v.as_str())
        .context("login did not return a token")?.to_string();
    println!("logged in as {}, token length {}", ident.username, token.len());

    let mut ws = net::ws::WsClient::connect(&srv.host, srv.api_port as u16, "/ws",
        net::tls::client_config(None), std::time::Duration::from_secs(10))?;
    println!("WebSocket handshake OK (101 + Sec-WebSocket-Accept check)");

    let connect_msg = serde_json::json!({
        "type": "connect",
        "payload": {"user_id": ident.username, "token": token},
        "request_id": "c1"
    });
    ws.send_text(&connect_msg.to_string())?;
    let mut connected = false;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline && !connected {
        if let Some(f) = ws.read_frame()? {
            if let net::ws::WsFrame::Text(t) = f {
                let v: serde_json::Value = serde_json::from_str(&t)?;
                if v.get("type").and_then(|x| x.as_str()) == Some("connect") {
                    connected = v.get("status").and_then(|x| x.as_str()) == Some("ok");
                    println!("  WS connect reply: {}", t);
                }
            }
        }
    }
    if !connected { anyhow::bail!("the server did not confirm the WS connection"); }

    let plain = "encrypted message from the Rust client: hello";
    let (ct, iv, tag, wrapped) = crypto::encrypt_text(plain, &peer_pub)?;
    let msg_id = crypto::generate_msg_id();
    let ts = crypto::now_secs();
    let fields = crypto::build_message_fields(
        &msg_id, &contact.username, &ident.username, ts, "", &ct, &iv, &tag, &wrapped,
        "", "", 0, "");
    let signature = crypto::sign_message(&ident.private_key, &fields)?;
    let payload = serde_json::json!({
        "to": contact.username, "ciphertext": ct, "iv": iv, "tag": tag,
        "msg_id": msg_id, "timestamp": ts, "wrapped_key": wrapped, "signature": signature
    });
    let send = serde_json::json!({"type":"send_message","payload":payload,"request_id":"c2"});
    ws.send_text(&send.to_string())?;
    println!("sent encrypted message -> {} (msg_id={})", contact.username, msg_id);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(12);
    let mut acked = false;
    while std::time::Instant::now() < deadline && !acked {
        match ws.read_frame() {
            Ok(Some(net::ws::WsFrame::Text(t))) => {
                let v: serde_json::Value = serde_json::from_str(&t)?;
                if v.get("type").and_then(|x| x.as_str()) == Some("send_message") {
                    println!("  server ack: {}", t);
                    if let Some(err) = v.pointer("/payload/error") {
                        println!("  ❌ rejected: {}", err);
                    } else {
                        println!("  ✅ the server verified the signature and accepted the message (delivered)");
                        acked = true;
                    }
                }
            }
            Ok(Some(net::ws::WsFrame::Ping(_))) => { /* tungstenite answers Pong automatically */ }
            Ok(Some(_)) | Ok(None) => {}
            Err(e) => { println!("  read finished: {e}"); break; }
        }
    }
    ws.send_close().ok();
    if !acked { anyhow::bail!("no success ack received"); }
    Ok(())
}


/// Diagnostic: print the keys crossterm parses (to confirm the encoding of Ctrl+Alt+M).
fn keytest() {
    use ratatui::crossterm::event::{self, Event as CtEvent};
    let mut t = ratatui::init();
    loop {
        // Once the terminal is gone crossterm spins on an internal read (see ui::terminal_hung_up); diagnostic mode must exit explicitly or it pins a core
        if msg_client_rust::ui::terminal_hung_up() {
            eprintln!("terminal closed, exiting keytest");
            break;
        }
        if event::poll(std::time::Duration::from_millis(100)).unwrap() {
            match event::read().unwrap() {
                CtEvent::Key(k) => {
                    log_key(&format!("KEY code={:?} mods={:?}", k.code, k.modifiers));
                    if matches!(k.code, ratatui::crossterm::event::KeyCode::Char('z')) { break; }
                }
                CtEvent::Mouse(m) => log_key(&format!("MOUSE {:?} col={} row={}", m.kind, m.column, m.row)),
                other => log_key(&format!("{other:?}")),
            }
        }
        let _ = &mut t;
    }
    ratatui::restore();
}


fn log_key(line: &str) {
    use std::io::Write;
    use std::sync::OnceLock;
    static T0: OnceLock<std::time::Instant> = OnceLock::new();
    let t0 = T0.get_or_init(std::time::Instant::now);
    let line = &format!("[{:>6.1}ms] {}", t0.elapsed().as_secs_f64()*1000.0, line);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/keytest.log") {
        let _ = writeln!(f, "{line}");
    }
}
