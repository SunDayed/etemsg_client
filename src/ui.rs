//! ratatui TUI: server/contact tree on the left, chat log + input on the right; keyboard-only.
//!
//! Layout matches the Python `chat_tui_linux` (F1-F9 button grid top-left).

use crate::core::{Core, Event, GroupOp};
use crate::store::{self, Store};
use anyhow::Result;
use ratatui::crossterm::event::{
    self, Event as CtEvent, KeyCode, KeyEvent, KeyModifiers,
};
use ratatui::crossterm::execute;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

const TOAST_SECS: u64 = 4;
const INITIAL_MSGS: i64 = 20;
const EARLIER_MSGS: i64 = 20;
const INPUT_CONTENT_LINES: usize = 3;
const INPUT_BOX_H: u16 = INPUT_CONTENT_LINES as u16 + 2;
const FILE_PICKER_VIS: usize = 14;

/// Group icon color: orange-yellow. Truecolor, so ratatui approximates it on lesser terminals;
/// deliberately not `Color::Yellow`, which is pure yellow.
const GROUP_ICON_COLOR: Color = Color::Rgb(255, 170, 0);
/// Top-left function buttons: 2 columns x 5 rows (F1-F4 1v1, F5-F9 groups).
/// Row index of F7 (notices) in [`BUTTON_ROWS`]; swapped for an alert label when work is pending.
const APPROVAL_BUTTON_ROW: usize = 2;
/// F7 label while notices are pending (same display width as the normal label, so the grid stays aligned).
const APPROVAL_LABEL_ALERT: &str = "Alerts F7";

/// Notice-center categories (top-level tree nodes).
const NOTICE_CATS: [&str; 4] = ["Group approval", "Group transfer", "Friend request", "Other messages"];

/// One pending item in the notice center.
#[derive(Clone)]
struct Notice {
    /// Category index into `NOTICE_CATS`
    cat: usize,
    /// Origin server: a friend request may arrive on any server and must be answered there.
    sid: String,
    /// Pre-rendered display text
    label: String,
    action: NoticeAction,
}

#[derive(Clone)]
enum NoticeAction {
    /// Join request: approving performs the MLS Add
    JoinRequest {
        gid: String,
        request_id: String,
    },
    /// Owner transfer awaiting my confirmation
    OwnerTransfer { gid: String },
    /// Someone added me one-way: confirm runs the existing "add contact by ID" flow
    FriendRequest { peer: String },
    /// Other messages can only be dismissed
    Dismiss,
}

/// Display width of a notice row (modal width minus borders/indent).
fn notice_label_width() -> usize {
    (modal_width(&Modal::Notices {
        rows: Vec::new(),
        sel: 0,
        expanded: [false; NOTICE_CATS.len()],
        msg: String::new(),
    }) as usize)
        .saturating_sub(6)
}

/// Flatten notices into navigable rows: `(category, index within category)`, `None` = category header.
fn notice_flat(rows: &[Notice], expanded: &[bool; NOTICE_CATS.len()]) -> Vec<(usize, Option<usize>)> {
    let mut out = Vec::new();
    for cat in 0..NOTICE_CATS.len() {
        out.push((cat, None));
        if expanded[cat] {
            for (i, n) in rows.iter().enumerate() {
                if n.cat == cat {
                    out.push((cat, Some(i)));
                }
            }
        }
    }
    out
}

const BUTTON_ROWS: [[&str; 2]; 5] = [
    ["Servers F1", "NewGroup F5"],
    ["Contact F2", "JoinGroup F6"],
    ["Files F3", "Messages F7"],
    ["Help F4", "SyncAll F8"],
    ["Members F9", ""],
];

#[derive(Clone, Copy, PartialEq)]
enum Focus {
    Tree,
    Input,
}

#[derive(Clone, PartialEq)]
enum TreeKind {
    Server,
    Contact,
    /// Group: the `contact` field holds the group_id (reused to avoid a second selection path)
    Group,
}

#[derive(Clone)]
struct TreeItem {
    kind: TreeKind,
    sid: String,
    contact: Option<String>,
    label: String,
    online: bool,
    expanded: bool,
    unread: i64,
}

enum Modal {
    Help,
    ServerList { sel: usize, form: Option<AddForm> },
    AddContact {
        id_field: String,
        name_field: String,
        focus: usize,
        msg: String,
        req: Option<String>,
        sent: bool,
    },
    RenameServer { sid: String, field: String },
    RenameContact { sid: String, contact: String, field: String },
    /// Rename group: changes the **group-wide shared** name via an MLS GroupContextExtensions commit
    RenameGroup { sid: String, gid: String, field: String, msg: String },
    FilePicker(FilePickerState),
    CreateGroup { name: String, nick: String, focus: usize, msg: String, busy: bool },
    JoinGroup { gid: String, text: String, nick: String, focus: usize, msg: String, busy: bool },
    GroupMembers {
        sid: String,
        gid: String,
        rows: Vec<(String, String, String)>, // (nickname, user_id, role)
        sel: usize,
    },
    /// Owner picks a successor; `for_leave` chooses "transfer + leave" vs "transfer only".
    PickSuccessor {
        sid: String,
        gid: String,
        rows: Vec<(String, String)>,
        sel: usize,
        for_leave: bool,
    },
    /// Notice center: tree of category -> item; Space expands/collapses, Enter/y accepts, n rejects.
    Notices {
        rows: Vec<Notice>,
        sel: usize,
        expanded: [bool; NOTICE_CATS.len()],
        msg: String,
    },
    Confirm { title: String, text: String, action: ConfirmAction },
}

#[derive(Debug)]
struct FileEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

struct FilePickerState {
    cwd: PathBuf,
    entries: Vec<FileEntry>,
    sel: usize,
    scroll: usize,
    /// Directory is being read on a background thread (a synchronous `read_dir` on a huge directory freezes the UI)
    loading: bool,
    /// Directory requested for this read; stale results arriving after the user moved on are discarded
    requested: PathBuf,
}

impl FilePickerState {
    fn ensure_visible(&mut self) {
        if self.sel < self.scroll {
            self.scroll = self.sel;
        } else if self.sel >= self.scroll + FILE_PICKER_VIS {
            self.scroll = self.sel + 1 - FILE_PICKER_VIS;
        }
    }
}

/// Background directory-read result (a huge directory can take hundreds of ms with `read_dir` + per-entry metadata).
#[derive(Debug)]
struct DirEntries {
    dir: PathBuf,
    entries: Vec<FileEntry>,
}

/// Read a directory: directories first, then case-insensitive name order. `DirEntry::file_type()`
/// decides the type and `metadata()` is only called for real files, cutting syscalls on big directories.
fn load_dir_entries(dir: &Path) -> DirEntries {
    let mut entries: Vec<FileEntry> = Vec::new();
    if let Some(parent) = dir.parent() {
        entries.push(FileEntry {
            name: "../".into(), path: parent.to_path_buf(), is_dir: true, size: 0 });
    }
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let ft = match ent.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            // Do not follow symlinks: a link to a directory counts as a file (existing behavior)
            let is_dir = ft.is_dir();
            let size = if is_dir {
                0
            } else {
                ent.metadata().map(|m| m.len()).unwrap_or(0)
            };
            entries.push(FileEntry {
                name: ent.file_name().to_string_lossy().to_string(),
                path: ent.path(),
                is_dir,
                size,
            });
        }
    }
    entries.sort_by(|a, b| {
        b.is_dir.cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    DirEntries { dir: dir.to_path_buf(), entries }
}

fn apply_dir_entries(st: &mut FilePickerState, res: DirEntries) {
    st.cwd = res.dir;
    st.entries = res.entries;
    st.sel = 0;
    st.scroll = 0;
    st.loading = false;
    st.requested = st.cwd.clone();
}

#[derive(Clone)]
enum ConfirmAction {
    DeleteServer(String),
    DeleteContact(String, String),
    /// Leave group (local cleanup + notify server). For an owner leaving, the third field is the successor's user_id.
    LeaveGroup(String, String, Option<String>),
    KickMember(String, String, String, String),
    TransferOwner(String, String, String, String),
    DissolveGroup(String, String),
    /// B5: quit confirmation when file downloads are in flight
    Quit,
}

#[derive(Default)]
struct AddForm {
    name: String,
    host: String,
    port: String,
    focus: usize,
}

pub struct Ui {
    pub store: Arc<Store>,
    pub core: Arc<Core>,
    pub events: Receiver<Event>,
    items: Vec<TreeItem>,
    sel: usize,
    tree_scroll: usize,
    collapsed: HashSet<String>,
    focus: Focus,
    input: String,
    input_cursor: usize,
    input_scroll: usize,
    drafts: std::collections::HashMap<(String, String), (String, usize)>,
    messages: Vec<store::MessageRow>,
    chat_scroll: usize,
    chat_total: i64,
    toast: Option<(String, Instant)>,
    modal: Option<Modal>,
    running: bool,
    last_size: (u16, u16),
    /// Needs redraw (avoids rebuilding the whole screen every 50ms while idle)
    dirty: bool,
    /// Time of the last lone Esc (to recognize Ctrl+Alt+M arriving as ESC then CR)
    last_esc: Option<Instant>,
    /// Nickname cache: server_id -> (username -> raw nickname Option); Option distinguishes "no nickname"
    /// from "nickname == user_id" and avoids a DB query per frame.
    nicks: std::collections::HashMap<String, std::collections::HashMap<String, Option<String>>>,
    /// Chat render-line cache: rebuilt only when the session switches, a message arrives, or the width changes
    chat_lines: Vec<Line<'static>>,
    chat_lines_w: u16,
    chat_dirty: bool,
    dir_tx: std::sync::mpsc::Sender<DirEntries>,
    dir_rx: Receiver<DirEntries>,
    /// **Group** chat target: the group_id, else None (1v1 contact).
    /// Kept out of `core.cur_contact`: that field feeds the 1v1 send path, and mixing in a group id would send group messages as 1v1.
    group_target: Option<String>,
    /// Pending join-request counts: `"sid|gid" -> count`; updated by `Event::GroupPendingApprovals` and
    /// cleared when the F7 approval modal opens.
    pending_approvals: std::collections::HashMap<String, usize>,
    /// "Other messages": local system notices (group dissolved/removed), appended by background events.
    system_notices: Vec<String>,
    /// Group-name cache: `"sid|gid" -> display name`. Decryption restores MLS state (disk round-trip), so it
    /// cannot run per frame; cleared on `GroupDirty` to reflect renames/new groups.
    group_names: std::collections::HashMap<String, String>,
    /// Unique id for the next background group operation, plus the currently pending one. The id is
    /// carried in `Event::GroupOpDone` so a late result cannot mutate a newer modal/selection.
    next_group_op_id: u64,
    pending_group_op: Option<(u64, GroupOp)>,
}

/// Whether the terminal is gone (PTY master closed / SSH dropped / terminal window closed).
///
/// **Must be backed by a dedicated thread**: once the master closes, the slave keeps `POLLHUP` forever and
/// crossterm's event-reader thread busy-spins on `read(0)` (measured: one core at 100%), while the main thread
/// blocks in `event::poll` and can never run the in-loop check. On a healthy terminal this returns instantly with no HUP.
pub fn terminal_hung_up() -> bool {
    use std::os::fd::AsRawFd;
    fd_hung_up(std::io::stdin().as_raw_fd())
}

/// Implementation of [`terminal_hung_up`] for an arbitrary fd (lets regression tests use a self-made PTY).
pub fn fd_hung_up(fd: libc::c_int) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: pfd is a valid stack pollfd, nfds=1, timeout=0 (non-blocking)
    let r = unsafe { libc::poll(&mut pfd, 1, 0) };
    r > 0 && (pfd.revents & libc::POLLHUP) != 0
}

#[cfg(test)]
mod hangup_tests {
    use super::fd_hung_up;

    /// **Regression**: closing the terminal (PTY master) must be detected as POLLHUP; it is the only reliable exit signal.
    #[test]
    fn pty_hangup_is_detected() {
        // SAFETY: only POSIX PTY calls; every fd is closed inside this test.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt failed");
            assert_eq!(libc::grantpt(master), 0, "grantpt failed");
            assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
            let name = libc::ptsname(master);
            assert!(!name.is_null(), "ptsname failed");
            let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(slave >= 0, "opening slave failed");

            // Master still open: no hangup may be reported (otherwise a healthy run would be killed)
            assert!(!fd_hung_up(slave), "POLLHUP must not be reported while master is open");

            libc::close(master);
            // The kernel needs a moment to propagate HUP
            std::thread::sleep(std::time::Duration::from_millis(200));
            assert!(fd_hung_up(slave), "POLLHUP must be reported after master closes");

            libc::close(slave);
        }
    }
}

impl Ui {
    pub fn new(store: Arc<Store>, core: Arc<Core>, events: Receiver<Event>) -> Self {
        let (dir_tx, dir_rx) = std::sync::mpsc::channel::<DirEntries>();
        Self {
            store, core, events,
            items: Vec::new(), sel: 0, tree_scroll: 0,
            collapsed: HashSet::new(), focus: Focus::Tree,
            input: String::new(), input_cursor: 0, input_scroll: 0,
            drafts: Default::default(), messages: Vec::new(),
            chat_scroll: 0, chat_total: 0, toast: None, modal: None,
            running: true, last_size: (0, 0), dirty: true, last_esc: None,
            nicks: Default::default(), chat_lines: Vec::new(),
            chat_lines_w: 0, chat_dirty: true,
            dir_tx, dir_rx,
            group_target: None,
            group_names: Default::default(),
            pending_approvals: Default::default(),
            system_notices: Vec::new(),
            next_group_op_id: 1,
            pending_group_op: None,
        }
    }

    pub fn run(mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        // No mouse reporting at all: the UI is keyboard-only
        // (also avoids a ?1003h mouse-move event flood burning CPU)
        let mut out = std::io::stdout();
        // Ask the terminal to report Ctrl+Alt+M precisely (terminals supporting the kitty keyboard protocol)
        let _ = execute!(out,
            ratatui::crossterm::event::PushKeyboardEnhancementFlags(
                ratatui::crossterm::event::KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
                    | ratatui::crossterm::event::KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES));
        // Enable bracketed paste: without it a multi-line paste is sent byte by byte, its CRs parsed
        // as Enter, and one paste becomes several messages sent early.
        let _ = execute!(out, event::EnableBracketedPaste);
        self.rebuild_tree();
        self.core.connect_all();
        // Group background threads must start here, at startup: they used to start only on a group push,
        // but pushes are best-effort (pre-login ones are lost) so a cold start might never run a worker,
        // not even the startup pending-approval rescan (F7 label and tree markers would never appear).
        for sid in self.core.live_order() {
            crate::group::runtime::start_worker(&self.core, &sid);
        }
        // -- Terminal watchdog --
        // The in-loop `terminal_hung_up()` check can never run once the terminal is gone (see that function),
        // so a dedicated thread covers it: on POLLHUP it stops the network threads, flushes the WAL and exits
        // (the terminal is gone, so its state can neither be restored nor needs to be).
        let core_for_watchdog = self.core.clone();
        std::thread::Builder::new()
            .name("tty-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(500));
                if terminal_hung_up() {
                    crate::tui_log!("terminal closed (POLLHUP); exiting to avoid a busy-spin burning CPU");
                    core_for_watchdog.shutdown();
                    // Also an "abnormal exit", so the WAL is flushed too
                    let _ = core_for_watchdog.store.checkpoint();
                    std::process::exit(0);
                }
            })
            .ok();
        let res = self.main_loop(terminal);
        // Shutdown: stop auto-reconnect and tell every WS thread to close its connection
        self.core.shutdown();
        // **Flush the WAL into the main DB before exiting**: `main` immediately calls `std::process::exit()`
        // (skipping destructors) and each WS/group-sync thread holds its own `Arc<Store>`, so SQLite's
        // "checkpoint on last connection close" never fires; without this `etemsg.db` stays stale with all
        // data in `-wal`, and copying only `etemsg.db` as a backup silently loses data.
        match self.store.checkpoint() {
            Ok(()) => crate::tui_log!("WAL flushed before exit (wal_checkpoint TRUNCATE)"),
            Err(e) => crate::tui_log!("failed to flush the WAL before exit (data is still in -wal and will be replayed on the next open): {e:#}"),
        }
        let mut out2 = std::io::stdout();
        let _ = execute!(out2, event::DisableBracketedPaste);
        let _ = execute!(out2,
            ratatui::crossterm::event::PopKeyboardEnhancementFlags);
        res
    }

    fn main_loop(&mut self, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
        let mut last_periodic = Instant::now();
        while self.running {
            self.drain_events();
            self.poll_dir_entries();
            let size = terminal.size().map(|s| (s.width, s.height)).unwrap_or((80, 24));
            if size != self.last_size {
                self.last_size = size;
                self.dirty = true;
            }
            let periodic = last_periodic.elapsed() > Duration::from_millis(500);
            if self.dirty || periodic {
                terminal.draw(|f| self.draw(f))?;
                self.dirty = false;
                if periodic { last_periodic = Instant::now(); }
            }
            // A vanished terminal (POLLHUP) must force an exit: otherwise the poll below returns true forever
            // and the loop degenerates into a 100% CPU busy-spin (see terminal_hung_up).
            if terminal_hung_up() {
                crate::tui_log!("terminal closed (POLLHUP); client exiting");
                return Ok(());
            }
            if event::poll(Duration::from_millis(50))? {
                // Same as above: the terminal can be closed during poll and read returns EOF;
                // a perpetual "event available" must not be mistaken for input.
                match event::read() {
                    Ok(CtEvent::Key(k)) => { self.handle_key(k); self.dirty = true; }
                    // B2: the whole paste arrives at once; insert it into the input, never trigger a send
                    Ok(CtEvent::Paste(text)) => { self.handle_paste(&text); self.dirty = true; }
                    Ok(CtEvent::Resize(..)) => { self.dirty = true; }
                    Ok(_) => {}
                    Err(_) => {
                        crate::tui_log!("failed to read a terminal event (the terminal may be closed); client exiting");
                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }

    // ---------------- events ----------------

    fn drain_events(&mut self) {
        while let Ok(ev) = self.events.try_recv() {
            self.dirty = true;
            match ev {
                Event::ServersChanged => self.rebuild_tree(),
                Event::UnreadChanged { server_id, contact, unread, delta } => {
                    self.apply_unread(&server_id, &contact, unread, delta);
                }
                Event::Toast(t) => self.set_toast(t),
                Event::LoginStatus { text } => self.set_toast(text),
                Event::LoginFinished { ok } => {
                    if ok {
                        let (n, total) = self.online_counts();
                        if total > 0 && n == total {
                            if let Some(Modal::ServerList { .. }) = self.modal {
                                self.modal = None;
                            }
                            self.set_toast(format!("connected to all {total} servers"));
                        }
                    }
                    self.rebuild_tree();
                }
                Event::ChatUpdated { server_id, contact } => {
                    if self.core.cur_server().as_deref() == Some(server_id.as_str())
                        && self.core.cur_contact().as_deref() == Some(contact.as_str())
                    {
                        self.reload_chat();
                    }
                }
                Event::PresenceChanged { .. } | Event::PresenceRefreshed { .. } => {
                    self.rebuild_tree();
                }
                Event::GroupPendingApprovals { server_id, group_id, count } => {
                    // The tree's "(pending N)" is persistent and must not depend on an expiring toast; count=0
                    // must **remove** the entry instead of storing 0, else the button-highlight check misfires.
                    let key = format!("{server_id}|{group_id}");
                    if count == 0 {
                        self.pending_approvals.remove(&key);
                    } else {
                        self.pending_approvals.insert(key, count);
                    }
                    self.rebuild_tree();
                }
                Event::GroupOpDone { id, op, ok, message } => {
                    let current = self.pending_group_op.as_ref().map(|(i, _)| *i) == Some(id);
                    if current {
                        self.pending_group_op = None;
                        self.handle_group_op_done(op, ok, message);
                    } else {
                        // A late result after the modal/selection changed: surface it, but do not mutate UI state.
                        self.set_toast(message);
                    }
                }
                Event::FriendRequest { sid, from } => {
                // **No toast here**: a toast fades in seconds yet F7 stays lit, and opening F7 then shows
                // nothing, because once the peer adds us back the one-way state is gone (that list queries it).
                // Keep it in the notice center's "other messages" instead: visible and dismissable.
                let text = format!("{}-{from} added you as a friend", self.server_label(&sid));
                if !self.system_notices.iter().any(|t| t == &text) {
                    self.system_notices.push(text);
                }
                self.pending_approvals
                    .insert(format!("{sid}|~friend"), 1);
                self.rebuild_tree();
                }
            // Local system notice (group invalidated, ...) -> "other messages"
            Event::SystemNotice(text) => {
                if !self.system_notices.iter().any(|t| t == &text) {
                    self.system_notices.push(text.clone());
                }
                self.set_toast(text);
            }
            Event::GroupDirty { server_id, group_id } => {
                    // Invalidate only this group's display name: clearing the whole map would restore every
                    // group's MLS state from the DB on the next tree rebuild (expensive).
                    self.group_names
                        .remove(&format!("{server_id}|{group_id}"));
                    let viewing = self.core.cur_server().as_deref() == Some(server_id.as_str())
                        && self.group_target.as_deref() == Some(group_id.as_str());
                    if viewing {
                        // Already viewing this group, so it must not accrue unread: unread is counted by the
                        // background decrypt thread, which does not know what the UI is viewing.
                        self.store.clear_group_unread(&server_id, &group_id).ok();
                    }
                    self.rebuild_tree();
                    // **Important**: setting chat_dirty alone is not enough -- that only rebuilds render
                    // lines, while `self.messages` still holds stale data, so re-read the DB when viewing.
                    if viewing {
                        self.reload_chat();
                    } else {
                        self.chat_dirty = true;
                    }
                }
                Event::AddContactResult { req_id, ok, message } => {
                    if let Some(Modal::AddContact { req, msg, sent, .. }) = &mut self.modal {
                        if req.as_deref() == Some(req_id.as_str()) {
                            *msg = message;
                            // Allow in-place edits and retries: reset sent, else Enter does nothing
                            if !ok { *sent = false; }
                        }
                        if ok { self.modal = None; }
                    }
                    self.rebuild_tree();
                }
            }
        }
    }

    /// Display name of the current server: the renamed display name if set, else `host:port`.
    /// Never the sid (an 8-char random hash, meaningless to users); backend calls still use the sid.
    fn current_server_label(&self) -> String {
        match self.core.cur_server() {
            Some(sid) => self.server_label(&sid),
            None => "no server selected".to_string(),
        }
    }

    fn server_label(&self, sid: &str) -> String {
        match self.core.session(sid) {
            Some(s) => {
                let name = s.name();
                if name.trim().is_empty() {
                    format!("{}:{}", s.host, s.port)
                } else {
                    name
                }
            }
            None => sid.to_string(),
        }
    }

    fn set_toast(&mut self, t: impl Into<String>) {
        let t = t.into();
        if !t.is_empty() {
            self.toast = Some((t, Instant::now()));
        }
    }

    fn online_counts(&self) -> (usize, usize) {
        let order = self.core.live_order();
        let total = order.len();
        let n = order.iter()
            .filter(|sid| self.core.session(sid).map(|s| s.status()).unwrap_or(false))
            .count();
        (n, total)
    }

    /// Incremental unread update: touches only the contact row and its server total, no full query/rebuild.
    /// Collapsed servers have no contact rows in `items`, so the total must accumulate deltas rather than re-sum.
    fn apply_unread(&mut self, sid: &str, contact: &str, unread: i64, delta: i64) {
        if let Some(it) = self.items.iter_mut().find(|i| {
            i.kind == TreeKind::Contact && i.sid == sid
                && i.contact.as_deref() == Some(contact)
        }) {
            it.unread = unread;
        }
        if let Some(sv) = self.items.iter_mut().find(|i| i.kind == TreeKind::Server && i.sid == sid) {
            sv.unread = (sv.unread + delta).max(0);
        }
    }

    fn rebuild_tree(&mut self) {
        let mut items = Vec::new();
        for sid in self.core.live_order() {
            let Some(sess) = self.core.session(&sid) else { continue };
            let online = sess.status();
            let expanded = !self.collapsed.contains(&sid);
            let contact_rows: Vec<store::Contact> = self.store.get_contacts(&sid)
                .unwrap_or_default().into_iter().filter(|c| c.deleted == 0).collect();
            let mut nick_map = std::collections::HashMap::new();
            for c in &contact_rows {
                // Cache the **raw nickname** (Option): it yields the display name and still distinguishes
                // "no nickname" from "nickname == user_id" (the rename modal needs the latter).
                let nick = c.nickname.clone().filter(|n| !n.is_empty());
                nick_map.insert(c.username.clone(), nick);
            }
            self.nicks.insert(sid.clone(), nick_map.clone());
            let unread_total: i64 = contact_rows.iter()
                .map(|c| sess.unread(&c.username)).sum();
            items.push(TreeItem {
                kind: TreeKind::Server, sid: sid.clone(), contact: None,
                label: format!("{}({}:{})", sess.name(), sess.host, sess.port),
                online, expanded, unread: unread_total,
            });
            if expanded {
                // Contact order: **online first**; the stable `sort_by_key` keeps DB order within a group
                // (no pinyin re-sorting).
                let online_set = sess.online_contacts_snapshot();
                let ordered = order_contacts_online_first(&contact_rows, &online_set);

                for c in ordered {
                    let nick = nick_map.get(&c.username).cloned().flatten()
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| c.username.clone());
                    // Dot = **is this contact online** (reported by the server); it must not reuse
                    // "is this client connected to that server".
                    let contact_online = online_set.contains(&c.username);
                    items.push(TreeItem {
                        kind: TreeKind::Contact, sid: sid.clone(),
                        contact: Some(c.username.clone()),
                        label: nick, online: contact_online, expanded: true,
                        unread: sess.unread(&c.username),
                    });
                }

                // Groups hang under the same expanded server, listing **joined** groups only (a group
                // whose join is still pending would have no MLS state and fail every send).
                for g in self.store.list_groups(&sid).unwrap_or_default() {
                    if !self.store.list_group_members(&sid, &g.group_id)
                        .unwrap_or_default()
                        .iter().any(|m| Some(&m.user_id) == self.core.username_of(&sid).as_ref())
                    {
                        continue;
                    }
                    let mut gname = self.group_display_name(&sid, &g.group_id)
                        .unwrap_or_else(|| g.group_id.clone());
                    // Pending approval is "work I must do", shown right after the name (toasts expire)
                    if let Some(n) = self
                        .pending_approvals
                        .get(&format!("{sid}|{}", g.group_id))
                        .copied()
                        .filter(|n| *n > 0)
                    {
                        gname = format!("{gname} (pending approval {n})");
                    }
                    let unread = self.store.group_unread(&sid, &g.group_id).unwrap_or(0);
                    items.push(TreeItem {
                        kind: TreeKind::Group, sid: sid.clone(),
                        contact: Some(g.group_id.clone()),
                        label: gname,
                        // Groups have no online state; the renderer ignores this field for them
                        online: false, expanded: true, unread,
                    });
                }
            }
        }
        self.items = items;
        if !self.items.is_empty() {
            self.sel = self.sel.min(self.items.len() - 1);
        } else {
            self.sel = 0;
        }
    }

    /// Group display name (cached). None on decrypt failure; the caller falls back to the group ID.
    fn group_display_name(&mut self, sid: &str, gid: &str) -> Option<String> {
        let key = format!("{sid}|{gid}");
        if let Some(v) = self.group_names.get(&key) {
            return Some(v.clone());
        }
        let name = crate::group::service::decrypt_group_name_local(&self.store, sid, gid)
            .ok()
            .flatten();
        if let Some(n) = &name {
            self.group_names.insert(key, n.clone());
        }
        name
    }

    fn selected_server_id(&self) -> Option<String> {
        self.items.get(self.sel.min(self.items.len().saturating_sub(1)))
            .map(|i| i.sid.clone())
            .or_else(|| self.core.cur_server())
    }

    fn client_id(&self) -> String {
        self.selected_server_id()
            .and_then(|sid| self.core.username_of(&sid))
            .or_else(|| self.core.cur_server().and_then(|s| self.core.username_of(&s)))
            .unwrap_or_else(|| "-".into())
    }

    /// Build the bubble lines for one message; shared by `rebuild_chat_lines` and the "load earlier" line count
    fn message_lines(&self, m: &store::MessageRow, inner_w: usize, me: &str) -> Vec<Line<'static>> {
        let inner_w = inner_w.max(10);
        let obj: serde_json::Value =
            serde_json::from_str(&m.content).unwrap_or(serde_json::Value::Null);
        let is_self = obj.get("from").and_then(|v| v.as_str()) == Some(me);
        let hhmm = store::hhmm(&m.time);
        // Group messages prefer the **in-group nickname** (from the MLS credential), then the
        // contact nickname, then the user_id (a group message's chat_key is the group_id).
        let in_group = self.group_target.as_deref() == Some(m.chat_key.as_str());
        let name = if is_self {
            "me".to_string()
        } else if in_group {
            self.store
                .group_member_nickname(&m.server_id, &m.chat_key, &m.sender)
                .ok()
                .flatten()
                .unwrap_or_else(|| m.sender.clone())
        } else {
            self.nick_of(&m.server_id, &m.sender)
        };
        let base_header = if is_self { format!("{hhmm} {name}") } else { format!("{name} {hhmm}") };
        // Own messages get a title suffix only when something is **actually wrong**: `queued` (offline
        // queue) and `delivered` (pushed to the peer) are both success, and flagging them would cry wolf.
        let (header, header_color) = if is_self {
            match local_status_suffix(obj.get(store::LOCAL_STATUS_KEY).and_then(|v| v.as_str())) {
                Some((suffix, color)) => (format!("{base_header}{suffix}"), color),
                None => (base_header, Color::Yellow),
            }
        } else {
            (base_header, Color::Yellow)
        };
        let body = if obj.get("msg_type").and_then(|v| v.as_str()) == Some("file") {
            let fname = obj.get("plain_filename").and_then(|v| v.as_str())
                .or_else(|| obj.get("filename").and_then(|v| v.as_str()))
                .unwrap_or("file");
            let size = obj.get("size").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64;
            let status = if is_self {
                String::new()
            } else if obj.get("original").and_then(|v| v.as_str())
                .map(|s| !s.is_empty()).unwrap_or(false) {
                "  downloaded".to_string()
            } else if obj.get("file_error").and_then(|v| v.as_str())
                .map(|s| !s.is_empty()).unwrap_or(false) {
                // A4/B3: file_error is written after 3 failed retries; surface it in the chat log
                "  ✗ receive failed".to_string()
            } else if let Some(pct) = obj.get("file_progress").and_then(|v| v.as_u64()) {
                // B5: resume/download progress (the download loop writes the percentage)
                format!("  receiving {pct}%")
            } else {
                "  receiving...".to_string()
            };
            format!("[file] {fname}  ({}){status}", fmt_size(size))
        } else if !m.plaintext.is_empty() {
            m.plaintext.clone()
        } else if let Some(o) = obj.get("original").and_then(|v| v.as_str()) {
            o.to_string()
        } else {
            "(encrypted message)".into()
        };
        let max_inner = ((inner_w as f32 * 0.68) as usize).max(6);
        let wrapped = wrap_display(&body, max_inner);
        let cw = wrapped.iter().map(|l| disp_width(l)).max().unwrap_or(2)
            .min(max_inner).max(2);
        let pad = inner_w.saturating_sub(cw + 4);
        let lead = if is_self { " ".repeat(pad) } else { String::new() };
        let align_header = if is_self {
            let hp = inner_w.saturating_sub(disp_width(&header));
            format!("{}{}", " ".repeat(hp), header)
        } else { header };

        let mut lines: Vec<Line<'static>> = Vec::with_capacity(wrapped.len() + 4);
        lines.push(Line::from(align_header).style(Style::default().fg(header_color)));
        lines.push(Line::from(format!("{lead}╭{}╮", "─".repeat(cw + 2)))
            .style(Style::default().fg(Color::Yellow)));
        for l in &wrapped {
            let padded = format!("{}{}", l, " ".repeat(cw.saturating_sub(disp_width(l))));
            lines.push(Line::from(format!("{lead}│ {padded} │")));
        }
        lines.push(Line::from(format!("{lead}╰{}╯", "─".repeat(cw + 2)))
            .style(Style::default().fg(Color::Yellow)));
        lines.push(Line::from(""));
        lines
    }

    /// Rebuild the chat render lines (only on session switch / new message / width change)
    fn rebuild_chat_lines(&mut self, inner_w: usize) {
        let inner_w = inner_w.max(10);
        let me = self.core.cur_server()
            .and_then(|s| self.core.username_of(&s)).unwrap_or_default();
        let mut lines: Vec<Line<'static>> = Vec::new();
        for m in &self.messages {
            lines.extend(self.message_lines(m, inner_w, &me));
        }
        self.chat_lines = lines;
        self.chat_lines_w = inner_w as u16;
        self.chat_dirty = false;
    }

    fn nick_of(&self, sid: &str, user: &str) -> String {
        self.custom_nick(sid, user).unwrap_or_else(|| user.to_string())
    }

    /// Stored raw nickname (None when unset).
    fn custom_nick(&self, sid: &str, user: &str) -> Option<String> {
        self.nicks.get(sid)
            .and_then(|m| m.get(user))
            .cloned()
            .flatten()
    }

    fn draft_key(&self) -> Option<(String, String)> {
        Some((self.core.cur_server()?, self.core.cur_contact()?))
    }
    fn save_draft(&mut self) {
        if let Some(k) = self.draft_key() {
            self.drafts.insert(k, (self.input.clone(), self.input_cursor));
        }
    }
    fn load_draft(&mut self) {
        let k = self.draft_key();
        let (t, c) = k.and_then(|k| self.drafts.get(&k).cloned()).unwrap_or_default();
        self.input = t;
        self.input_cursor = c.min(self.input.chars().count());
        self.input_scroll = 0;
        self.ensure_input_cursor_visible();
    }

    /// Clear the current session's on-screen state (messages / render lines / scroll).
    /// Used for "no session selected" and after deleting the current one, so deleted plaintext is not shown.
    fn clear_chat_view(&mut self) {
        self.messages.clear();
        self.chat_total = 0;
        self.chat_lines.clear();
        self.chat_lines_w = 0;
        self.chat_scroll = 0;
        self.chat_dirty = true;
    }

    fn reload_chat(&mut self) {
        let Some(sid) = self.core.cur_server() else {
            self.clear_chat_view();
            return;
        };
        // Group chat reads the local group-message table and **synthesizes** MessageRow to reuse bubble rendering
        if let Some(gid) = self.group_target.clone() {
            match self.store.list_group_messages(&sid, &gid, 0) {
                Ok(rows) => {
                    self.messages = rows
                        .into_iter()
                        .map(|m| store::MessageRow {
                            id: m.seq as i64,
                            server_id: sid.clone(),
                            chat_key: gid.clone(),
                            msg_id: Some(m.msg_id.clone()),
                            sender: m.sender.clone(),
                            content: serde_json::json!({ "from": m.sender }).to_string(),
                            time: m.time.clone(),
                            plaintext: m.plaintext.clone(),
                        })
                        .collect();
                    self.chat_total = self.messages.len() as i64;
                }
                Err(e) => {
                    self.clear_chat_view();
                    self.set_toast(format!("failed to load group messages: {e:#}"));
                }
            }
            self.chat_dirty = true;
            self.chat_scroll = 0;
            return;
        }
        let Some(contact) = self.core.cur_contact() else {
            self.clear_chat_view();
            return;
        };
        match self.core.load_messages(&sid, &contact, INITIAL_MSGS) {
            Ok((rows, total)) => {
                self.messages = rows;
                self.chat_total = total;
            }
            Err(e) => {
                // The old `if let Ok(..)` kept the previous session's `messages` on query failure and the UI
                // showed the **previous contact's** content (cross-session leakage); now clear and report.
                self.clear_chat_view();
                self.set_toast(format!("failed to load chat history: {e:#}"));
            }
        }
        self.chat_dirty = true;      // rebuild chat lines on the next frame (not every frame)
        self.chat_scroll = 0;
    }

    // ---------------- paste ----------------

    /// Handle bracketed paste: insert the whole text at once, **never send**; newlines are normalized
    /// (`\r\n` / `\r` -> `\n`) and other control characters dropped so terminal CR semantics cannot leak in.
    fn handle_paste(&mut self, text: &str) {
        // Single-line modal fields must accept paste too (contact/group IDs are **meant to be copied in**),
        // and the old build swallowed paste in every modal, forcing users to type them character by character.
        if self.modal.is_some() {
            self.paste_into_modal(text);
            return;
        }
        if self.focus != Focus::Input {
            return;
        }
        let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
        let cleaned: String = normalized.chars()
            .filter(|c| *c == '\n' || *c == '\t' || !c.is_control())
            .collect();
        if cleaned.is_empty() {
            return;
        }
        self.insert_str(&cleaned);
        self.after_input_change();
    }

    /// Push pasted text into the modal's focused field: ID fields strip all whitespace and try to pick
    /// out a 10-char ID (users often copy a whole sentence); name/nickname/note fields only drop CR and TAB.
    fn paste_into_modal(&mut self, text: &str) {
        let raw = text.replace("\r\n", "\n").replace('\r', "\n");
        let single: String = raw
            .chars()
            .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
            .filter(|c| !c.is_control())
            .collect();
        let plain = single.trim().to_string();
        let as_id = extract_id_token(&plain).unwrap_or_else(|| plain.replace(' ', ""));
        if plain.is_empty() {
            return;
        }

        let Some(m) = self.modal.as_mut() else { return };
        match m {
            Modal::AddContact { id_field, name_field, focus, .. } => {
                if *focus == 0 {
                    id_field.push_str(&as_id);
                } else {
                    name_field.push_str(&plain);
                }
            }
            Modal::JoinGroup { gid, text: desc, nick, focus, .. } => match *focus {
                0 => gid.push_str(&as_id),
                1 => desc.push_str(&plain),
                _ => nick.push_str(&plain),
            },
            Modal::CreateGroup { name, nick, focus, .. } => {
                if *focus == 0 {
                    name.push_str(&plain);
                } else {
                    nick.push_str(&plain);
                }
            }
            Modal::RenameServer { field, .. }
            | Modal::RenameContact { field, .. }
            | Modal::RenameGroup { field, .. } => field.push_str(&plain),
            _ => {}
        }
    }

    /// Request quit: confirm while downloads are in flight, else just stop the main loop.
    /// A separate method so the **terminal-independent quit entry** can reuse it (see `q` in the F1 modal):
    /// some terminals (Xshell, ...) never send Ctrl+Alt+M, and guessing key encodings cannot fix that.
    /// some terminals (Xshell, ...) never send Ctrl+Alt+M, and guessing key encodings cannot fix that.
    fn request_quit(&mut self) {
        self.last_esc = None;
        let n = self.core.active_downloads();
        if n > 0 {
            let text = format!(
                "{n} file(s) are still being received.\n\n\
                 quitting interrupts them; parts received so far stay in\n\
                 received_files/.part/ and resume when you reconnect.\n\n\
                 Quit now?");
            self.modal = Some(Modal::Confirm {
                title: " Confirm quit ".into(),
                text,
                action: ConfirmAction::Quit,
            });
            return;
        }
        self.running = false;
    }

    // ---------------- input ----------------
    fn handle_key(&mut self, k: KeyEvent) {
        // ---- global quit: Ctrl+Alt+M ----
        if is_exit_key(&k, self.last_esc) {
            self.request_quit();
            return;
        }
        self.last_esc = None;
        // Record a lone Esc only when no modal is open, so "Esc closes modal then Enter"
        // is not read as the ESC+CR form of Ctrl+Alt+M (see is_exit_key).
        if matches!(k.code, KeyCode::Esc) && self.modal.is_none() {
            self.last_esc = Some(Instant::now());
        }
        if k.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(k.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            return;
        }
        if self.modal.is_some() {
            self.handle_modal_key(k);
            return;
        }
        match k.code {
            KeyCode::F(1) => self.modal = Some(Modal::ServerList { sel: 0, form: None }),
            KeyCode::F(2) => {
                self.modal = Some(Modal::AddContact {
                    id_field: String::new(),
                    name_field: String::new(),
                    focus: 0,
                    msg: "Enter submit · Tab/↑↓ switch to name (optional)".into(),
                    req: None,
                    sent: false,
                })
            }
            KeyCode::F(3) => self.open_file_picker(),
            KeyCode::F(4) => self.modal = Some(Modal::Help),
            KeyCode::F(5) => {
                self.modal = Some(Modal::CreateGroup {
                    name: String::new(),
                    nick: String::new(),
                    focus: 0,
                    msg: "group name is encrypted; nickname is sent to members via MLS".into(),
                    busy: false,
                })
            }
            KeyCode::F(6) => {
                self.modal = Some(Modal::JoinGroup {
                    gid: String::new(),
                    text: String::new(),
                    nick: String::new(),
                    focus: 0,
                    msg: "request note is encrypted; nickname is sent to members via MLS".into(),
                    busy: false,
                })
            }
            KeyCode::F(7) => self.open_notices(),
            KeyCode::F(8) => self.sync_current_group_manual(),
            KeyCode::F(9) => self.open_group_members(),
            KeyCode::Tab => {
                self.focus = if self.focus == Focus::Tree { Focus::Input } else { Focus::Tree };
            }
            _ if self.focus == Focus::Input => self.handle_input_key(k),
            _ => self.handle_tree_key(k),
        }
    }

    fn handle_input_key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Esc => self.focus = Focus::Tree,
            // Newline: Shift+Enter (needs the kitty protocol), Ctrl+J (universal; parsed in raw mode as
            // Char('j')+CONTROL), Ctrl+Enter (some terminals)
            KeyCode::Enter if k.modifiers.contains(KeyModifiers::SHIFT) => self.insert_char('\n'),
            KeyCode::Enter if k.modifiers.contains(KeyModifiers::CONTROL) => self.insert_char('\n'),
            KeyCode::Char('j') | KeyCode::Char('J')
                if k.modifiers.contains(KeyModifiers::CONTROL) => self.insert_char('\n'),
            KeyCode::Enter => self.send_input(),
            KeyCode::PageUp => self.chat_page(-1),
            KeyCode::PageDown => self.chat_page(1),
            KeyCode::Up => self.input_move_line(-1),
            KeyCode::Down => self.input_move_line(1),
            KeyCode::Left => {
                self.input_cursor = self.input_cursor.saturating_sub(1);
                self.after_input_change();
            }
            KeyCode::Right => {
                let n = self.input.chars().count();
                self.input_cursor = (self.input_cursor + 1).min(n);
                self.after_input_change();
            }
            KeyCode::Home => {
                let (line, _) = self.input_cursor_line_col();
                self.input_cursor = self.input_line_meta()[line].0;
                self.after_input_change();
            }
            KeyCode::End => {
                let (line, _) = self.input_cursor_line_col();
                let meta = self.input_line_meta();
                self.input_cursor = meta[line].0 + meta[line].1;
                self.after_input_change();
            }
            KeyCode::Backspace => {
                if self.input_cursor > 0 {
                    self.remove_char_at(self.input_cursor - 1);
                }
                self.after_input_change();
            }
            KeyCode::Delete => {
                if self.input_cursor < self.input.chars().count() {
                    self.remove_char_at(self.input_cursor);
                }
                self.after_input_change();
            }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                self.insert_char(c);
            }
            _ => {}
        }
    }

    /// Per line (start char index, char length); at least one line
    fn input_line_meta(&self) -> Vec<(usize, usize)> {
        line_meta(&self.input)
    }

    /// Caret position: (line, char offset within the line)
    fn input_cursor_line_col(&self) -> (usize, usize) {
        cursor_line_col(&self.input, self.input_cursor)
    }

    /// Caret's display column on the current line (CJK/full-width count as 2)
    fn input_cursor_display_col(&self) -> usize {
        let (line, col) = self.input_cursor_line_col();
        let text = self.input.split('\n').nth(line).unwrap_or("");
        let before: String = text.chars().take(col).collect();
        disp_width(&before)
    }

    fn insert_char(&mut self, c: char) {
        let mut v: Vec<char> = self.input.chars().collect();
        let pos = self.input_cursor.min(v.len());
        v.insert(pos, c);
        self.input = v.into_iter().collect();
        self.input_cursor = pos + 1;
        self.after_input_change();
    }

    /// Insert text at the caret (bracketed paste). Does not call `after_input_change` itself;
    /// the caller handles it once after the whole insert, avoiding per-char scroll/draft writes.
    fn insert_str(&mut self, s: &str) {
        let mut v: Vec<char> = self.input.chars().collect();
        let pos = self.input_cursor.min(v.len());
        let added: Vec<char> = s.chars().collect();
        let n = added.len();
        for (i, c) in added.into_iter().enumerate() {
            v.insert(pos + i, c);
        }
        self.input = v.into_iter().collect();
        self.input_cursor = pos + n;
    }

    fn remove_char_at(&mut self, pos: usize) {
        let mut v: Vec<char> = self.input.chars().collect();
        if pos < v.len() {
            v.remove(pos);
            self.input = v.into_iter().collect();
            if self.input_cursor > pos { self.input_cursor -= 1; }
        }
    }

    fn input_move_line(&mut self, dir: i32) {
        let (line, col) = self.input_cursor_line_col();
        let meta = self.input_line_meta();
        let target = if dir < 0 {
            if line == 0 { return; }
            line - 1
        } else {
            if line + 1 >= meta.len() { return; }
            line + 1
        };
        let (start, len) = meta[target];
        self.input_cursor = start + col.min(len);
        self.after_input_change();
    }

    fn after_input_change(&mut self) {
        self.ensure_input_cursor_visible();
        self.save_draft();
    }

    fn ensure_input_cursor_visible(&mut self) {
        let (line, _) = self.input_cursor_line_col();
        let vis = INPUT_CONTENT_LINES;
        if line < self.input_scroll {
            self.input_scroll = line;
        } else if line >= self.input_scroll + vis {
            self.input_scroll = line + 1 - vis;
        }
    }

    /// Keys for tree focus. Only `d` (delete, confirmed) and `r` (rename server) remain;
    /// **add contact / server config / send file / help all moved to F1-F4** to stop bare letters
    /// (a/s/h/?) from misfiring, especially Ctrl+D / Ctrl+R, which used to hit the same branch.
    fn handle_tree_key(&mut self, k: KeyEvent) {
        match k.code {
            KeyCode::Up => self.sel = self.sel.saturating_sub(1),
            KeyCode::Down => {
                if !self.items.is_empty() { self.sel = (self.sel + 1).min(self.items.len() - 1); }
            }
            KeyCode::Home => self.sel = 0,
            KeyCode::End => self.sel = self.items.len().saturating_sub(1),
            KeyCode::PageUp => {
                let page = self.list_page();
                self.sel = self.sel.saturating_sub(page);
            }
            KeyCode::PageDown => {
                let page = self.list_page();
                if !self.items.is_empty() { self.sel = (self.sel + page).min(self.items.len() - 1); }
            }
            KeyCode::Enter => self.activate_selected(),
            KeyCode::Char(' ') => {
                if let Some(it) = self.items.get(self.sel) {
                    if it.kind == TreeKind::Server {
                        let sid = it.sid.clone();
                        if !self.collapsed.remove(&sid) { self.collapsed.insert(sid); }
                        self.rebuild_tree();
                    }
                }
            }
            // Accept bare letters only without CONTROL/ALT, so Ctrl+D / Ctrl+R cannot delete/rename
            KeyCode::Char(c) if !k.modifiers.intersects(
                KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER) => {
                self.handle_tree_char(c)
            }
            _ => {}
        }
    }

    fn successor_candidates(
        &self,
        sid: &str,
        gid: &str,
        me: Option<&str>,
    ) -> Vec<(String, String)> {
        self.store
            .list_group_members(sid, gid)
            .unwrap_or_default()
            .iter()
            .filter(|m| Some(m.user_id.as_str()) != me)
            .map(|m| {
                let nick = if m.nickname.is_empty() {
                    m.user_id.clone()
                } else {
                    format!("{} <{}>", m.nickname, m.user_id)
                };
                (nick, m.user_id.clone())
            })
            .collect()
    }

    fn handle_tree_char(&mut self, c: char) {
        match c {
            'r' => {
                if let Some(it) = self.items.get(self.sel) {
                    match it.kind {
                        TreeKind::Server => {
                            let sid = it.sid.clone();
                            let name = self.core.session(&sid).map(|s| s.name())
                                .unwrap_or_else(|| it.label.clone());
                            self.modal = Some(Modal::RenameServer { sid, field: name });
                        }
                        TreeKind::Contact => {
                            let sid = it.sid.clone();
                            let contact = it.contact.clone().unwrap_or_default();
                            if contact.is_empty() { return; }
                            // Prefill the **stored nickname** (not the display name): empty when unset, so a
                            // user_id can never be written back as a nickname.
                            let field = self.custom_nick(&sid, &contact).unwrap_or_default();
                            self.modal = Some(Modal::RenameContact { sid, contact, field });
                        }
                        // The group name is group-wide shared state: changing it commits an MLS
                        // GroupContextExtensions, which other members merge; new members get it from the Welcome.
                        TreeKind::Group => {
                            let sid = it.sid.clone();
                            let gid = it.contact.clone().unwrap_or_default();
                            if gid.is_empty() {
                                return;
                            }
                            let field = self
                                .group_display_name(&sid, &gid)
                                .unwrap_or_default();
                            self.modal = Some(Modal::RenameGroup {
                                sid,
                                gid,
                                field,
                                msg: "renaming broadcasts one MLS commit (rotates keys)".into(),
                            });
                        }
                    }
                }
            }
            'd' => self.confirm_delete_selected(),
            // `t`: **transfer ownership only** (I stay in the group and keep approving joins);
            // distinct from `d` (transfer and leave).
            't' => {
                let Some(it) = self.items.get(self.sel).cloned() else { return };
                if it.kind != TreeKind::Group {
                    return;
                }
                let gid = it.contact.clone().unwrap_or_default();
                if gid.is_empty() {
                    return;
                }
                let me = self.core.username_of(&it.sid);
                let my_role = self
                    .store
                    .get_group(&it.sid, &gid)
                    .ok()
                    .flatten()
                    .map(|g| g.my_role);
                if my_role != Some(crate::group::state::GroupRole::Owner) {
                    self.set_toast("only the owner can transfer ownership".to_string());
                    return;
                }
                let others = self.successor_candidates(&it.sid, &gid, me.as_deref());
                if others.is_empty() {
                    self.set_toast("no other member can take over".to_string());
                    return;
                }
                self.modal = Some(Modal::PickSuccessor {
                    sid: it.sid.clone(),
                    gid,
                    rows: others,
                    sel: 0,
                    for_leave: false,
                });
            }
            // `D` (Shift+d): dissolve the group (owner only, irreversible)
            'D' => {
                let Some(it) = self.items.get(self.sel).cloned() else { return };
                if it.kind != TreeKind::Group {
                    return;
                }
                let gid = it.contact.clone().unwrap_or_default();
                if gid.is_empty() {
                    return;
                }
                self.modal = Some(Modal::Confirm {
                    title: "Dissolve group".into(),
                    text: format!(
                        "Dissolve {}?\n\n\n· every member's local copy is removed on the next sync;\n· **cannot be undone**.",
                        it.label
                    ),
                    action: ConfirmAction::DissolveGroup(it.sid.clone(), gid),
                });
            }
            _ => {}
        }
    }

    fn list_page(&self) -> usize {
        let h = self.last_size.1.saturating_sub(12) as usize;
        h.max(1)
    }

    fn activate_selected(&mut self) {
        let Some(it) = self.items.get(self.sel).cloned() else { return };
        match it.kind {
            TreeKind::Server => {
                if !self.collapsed.remove(&it.sid) { self.collapsed.insert(it.sid); }
                self.rebuild_tree();
            }
            TreeKind::Contact => {
                self.save_draft();
                let contact = it.contact.clone().unwrap_or_default();
                if self.core.cur_server().as_deref() != Some(it.sid.as_str()) {
                    *self.core.current_server.lock().unwrap() = Some(it.sid.clone());
                    *self.core.current_contact.lock().unwrap() = None;
                }
                *self.core.current_contact.lock().unwrap() = Some(contact.clone());
                // Switching from a group back to a contact must clear the group target, or Enter sends as a group message
                self.group_target = None;
                self.store.set_unread(&it.sid, &contact, 0).ok();
                if let Some(s) = self.core.session(&it.sid) {
                    s.state.lock().unwrap().unread.insert(contact.clone(), 0);
                }
                self.load_draft();
                self.reload_chat();
                self.focus = Focus::Input; // focus the input box after selecting a contact
                self.rebuild_tree();
            }
            TreeKind::Group => {
                self.save_draft();
                let gid = it.contact.clone().unwrap_or_default();
                *self.core.current_server.lock().unwrap() = Some(it.sid.clone());
                // Clear the 1v1 current contact: group chat does not use Core's 1v1 send path
                *self.core.current_contact.lock().unwrap() = None;
                self.group_target = Some(gid.clone());
                self.store.clear_group_unread(&it.sid, &gid).ok();
                self.load_draft();
                // Pull once on entering to catch up on the offline backlog
                self.sync_current_group();
                self.reload_chat();
                self.focus = Focus::Input;
                self.rebuild_tree();
            }
        }
    }

    /// F7: fetch the current group's pending join requests (they are decrypted and shown locally).
    /// Open the **notice center** (F7): pending work aggregated across servers and groups.
    ///
    /// Four categories: group approvals (join requests), group transfers (awaiting me), friend requests
    /// (someone added me one-way), other messages (system notices such as a dead group). Friend requests
    /// can arrive on any server, so `Notice.sid` travels with the entry and "currently selected server" must not be used.
    fn open_notices(&mut self) {
        // Server display name (each notice label embeds the server name)
        let mut srv: std::collections::HashMap<String, String> = Default::default();
        for sid in self.core.live_order() {
            let sess = self.core.session(&sid);
            // `name()` already defaults to "host:port"; do not append the port again (1.2.3.4:5:5)
            let name = sess
                .as_ref()
                .map(|s| {
                    let n = s.name();
                    if n.ends_with(&format!(":{}", s.port)) {
                        n
                    } else {
                        format!("{n}:{}", s.port)
                    }
                })
                .unwrap_or_else(|| sid.clone());
            srv.insert(sid, name);
        }
        let mut rows: Vec<Notice> = Vec::new();
        let servers: Vec<String> = self.core.live_order();
        for sid in &servers {
            let sname = srv.get(sid).cloned().unwrap_or_else(|| sid.clone());
            // -- Friend requests: SERVER - PEER_ID --
            match self.core.fetch_pending_contacts(sid) {
                Ok(peers) => {
                for peer in peers {
                    rows.push(Notice {
                        cat: 2,
                        sid: sid.clone(),
                        label: format!("{sname}-{peer}"),
                        action: NoticeAction::FriendRequest { peer },
                    });
                }
                }
                // Fetch failures must be visible: an empty list otherwise looks like "nobody added me"
                Err(e) => rows.push(Notice {
                    cat: 3,
                    sid: sid.clone(),
                    label: format!("{sname} failed to fetch friend requests: {e:#}"),
                    action: NoticeAction::Dismiss,
                }),
            }
            // -- Group approvals / group transfers --
            let groups = self.store.list_groups(sid).unwrap_or_default();
            let Ok(svc) = crate::group::runtime::service_for(&self.core, sid) else {
                continue;
            };
            for g in groups {
                let gname = self
                    .group_display_name(sid, &g.group_id)
                    .unwrap_or_else(|| g.group_id.clone());
                // Transfers: only those "awaiting my confirmation"
                if let Ok(Some(t)) = svc.pending_owner_transfer(&g.group_id) {
                    if self.core.username_of(sid).as_deref() == Some(t.designee.as_str()) {
                        rows.push(Notice {
                            cat: 1,
                            sid: sid.clone(),
                            label: format!("<{gname}>-({}) owner transfer to you", g.group_id),
                            action: NoticeAction::OwnerTransfer {
                                gid: g.group_id.clone(),
                            },
                        });
                    }
                }
                // Approvals: only owner/admin can fetch them
                if g.my_role.can_commit() {
                    if let Ok(reqs) = svc.list_join_requests(&g.group_id) {
                        for (r, text) in reqs {
                            let who = svc
                                .applicant_nickname(&g.group_id, &r.kp_id)
                                .map(|n| format!("{n} <{}>", r.applicant))
                                .unwrap_or_else(|| r.applicant.clone());
                            rows.push(Notice {
                                cat: 0,
                                sid: sid.clone(),
                                label: format!(
                                    "{sname}-{who} requests to join <{gname}> ({}), {text}",
                                    g.group_id
                                ),
                                action: NoticeAction::JoinRequest {
                                    gid: g.group_id.clone(),
                                    request_id: r.request_id,
                                },
                            });
                        }
                    }
                }
            }
        }
        // -- Other messages: local system notices (dead group, ...) --
        for text in &self.system_notices {
            rows.push(Notice {
                cat: 3,
                sid: String::new(),
                label: text.clone(),
                action: NoticeAction::Dismiss,
            });
        }
        // Seen by the user: clear F7's persistent alert
        self.pending_approvals.clear();
        self.rebuild_tree();
        self.modal = Some(Modal::Notices {
            rows,
            sel: 0,
            expanded: [true, true, true, true],
            msg: "↑↓ select   Space expand/collapse   Enter/y accept   n reject".into(),
        });
    }
    fn open_group_members(&mut self) {
        let Some(sid) = self.core.cur_server() else {
            self.set_toast("select a server first".to_string());
            return;
        };
        let gid = self
            .items
            .get(self.sel)
            .filter(|i| matches!(i.kind, TreeKind::Group))
            .and_then(|i| i.contact.clone())
            .or_else(|| self.group_target.clone());
        let Some(gid) = gid else {
            self.set_toast("select a group first".to_string());
            return;
        };
        let me = self.core.username_of(&sid);
        let rows: Vec<(String, String, String)> = self
            .store
            .list_group_members(&sid, &gid)
            .unwrap_or_default()
            .into_iter()
            .map(|m| {
                let nick = if m.nickname.is_empty() {
                    "(not set)".to_string()
                } else {
                    m.nickname.clone()
                };
                let nick = if Some(&m.user_id) == me.as_ref() {
                    format!("{nick} (me)")
                } else {
                    nick
                };
                let role = match m.role {
                    crate::group::state::GroupRole::Owner => "owner",
                    crate::group::state::GroupRole::Admin => "admin",
                    crate::group::state::GroupRole::Member => "member",
                };
                (nick, m.user_id, role.to_string())
            })
            .collect();
        self.modal = Some(Modal::GroupMembers { sid, gid, rows, sel: 0 });
    }

    /// F8: manually sync the current group (fetch and decrypt new messages). **Not needed to join**: once
    /// approved, the server pushes `group_notify(reason=welcome)` and the background thread consumes the
    /// Welcome automatically; this is only a fallback for a lost push.
    /// After a group key rotation breaks a send: sync this group at once (merge new commits) and nudge the background thread.
    fn sync_after_epoch_rotation(&mut self, sid: &str, gid: &str) {
        if let Some(sess) = self.core.session(sid) {
            sess.group_runtime.mark(sid, gid);
        }
        if let Ok(svc) = crate::group::runtime::service_for(&self.core, sid) {
            let _ = svc.sync_group(gid);
        }
        crate::group::runtime::start_worker(&self.core, sid);
    }

    fn sync_current_group_manual(&mut self) {
        let Some(sid) = self.core.cur_server() else {
            self.set_toast("select a server first".to_string());
            return;
        };
        let gid = self.group_target.clone();
        let r = crate::group::runtime::service_for(&self.core, &sid).and_then(|svc| match &gid {
            Some(g) => svc.sync_group(g).map(|n| format!("{n} new message(s)")),
            None => crate::group::runtime::sync_all(&self.core, &sid).map(|v| {
                let total: usize = v.iter().map(|(_, n)| n).sum();
                format!("{} groups, {total} new messages", v.len())
            }),
        });
        match r {
            Ok(msg) => {
                self.reload_chat();
                self.set_toast(format!("synced ({msg})"));
            }
            Err(e) => self.set_toast(format!("sync failed: {e:#}")),
        }
    }

    /// Background-sync the current group (non-blocking: its own worker pulls while the UI only reads the local DB).
    fn sync_current_group(&mut self) {
        let (Some(sid), Some(gid)) = (self.core.cur_server(), self.group_target.clone()) else {
            return;
        };
        if let Some(sess) = self.core.session(&sid) {
            sess.group_runtime.mark(&sid, &gid);
            crate::group::runtime::start_worker(&self.core, &sid);
        }
    }

    fn confirm_delete_selected(&mut self) {
        let Some(it) = self.items.get(self.sel).cloned() else { return };
        match it.kind {
            TreeKind::Server => {
                self.modal = Some(Modal::Confirm {
                    title: "Confirm delete".into(),
                    text: format!("Delete server {}?\nIts identity, contacts and chat history are all removed.", it.label),
                    action: ConfirmAction::DeleteServer(it.sid),
                });
            }
            TreeKind::Contact => {
                self.modal = Some(Modal::Confirm {
                    title: "Confirm delete".into(),
                    text: format!("Permanently delete contact {}?", it.label),
                    action: ConfirmAction::DeleteContact(it.sid, it.contact.unwrap_or_default()),
                });
            }
            TreeKind::Group => {
                let sid = it.sid.clone();
                let gid = it.contact.clone().unwrap_or_default();
                if gid.is_empty() {
                    return;
                }
                // An owner leaving must name a successor: otherwise nobody can push commits and renames,
                // kicks, adds and removal reconciliation break forever. Ask for the successor first.
                let me = self.core.username_of(&sid);
                let my_role = self
                    .store
                    .get_group(&sid, &gid)
                    .ok()
                    .flatten()
                    .map(|g| g.my_role);
                let others = self.successor_candidates(&sid, &gid, me.as_deref());

                if my_role == Some(crate::group::state::GroupRole::Owner) && !others.is_empty() {
                    self.modal = Some(Modal::PickSuccessor {
                        sid,
                        gid,
                        rows: others,
                        sel: 0,
                        for_leave: true,
                    });
                } else {
                    self.modal = Some(Modal::Confirm {
                        title: "Leave group".into(),
                        text: format!(
                            "Leave {}?\nThe local MLS state and messages for this group are cleared.",
                            it.label
                        ),
                        action: ConfirmAction::LeaveGroup(sid, gid, None),
                    });
                }
            }
        }
    }

    /// Open the F3 file picker (starting directory = the process CWD)
    fn open_file_picker(&mut self) {
    // No files in group chat: F3 uses the **1v1** path (recipient = current contact), and a group has no
    // single recipient, so a forced send would go to the wrong peer or simply fail; block it and say why.
    if self.group_target.is_some() {
        self.set_toast("file send/download is not supported in groups yet".to_string());
        return;
    }
        if self.core.cur_server().is_none() || self.core.cur_contact().is_none() {
            self.set_toast("select a server and a contact first");
            return;
        }
        let start = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let st = FilePickerState {
            cwd: start.clone(),
            entries: Vec::new(),
            sel: 0,
            scroll: 0,
            loading: true,
            requested: start.clone(),
        };
        self.modal = Some(Modal::FilePicker(st));
        self.request_dir_load(start);
    }

    /// B4: ask a background thread to read the directory; `poll_dir_entries` applies the result in the main loop.
    fn request_dir_load(&self, dir: PathBuf) {
        let tx = self.dir_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(load_dir_entries(&dir));
        });
    }

    /// B4: apply a completed background directory read to the file picker.
    fn poll_dir_entries(&mut self) {
        while let Ok(res) = self.dir_rx.try_recv() {
            if let Some(Modal::FilePicker(st)) = &mut self.modal {
                // Drop a stale result that arrives after the user switched to another directory
                if res.dir == st.requested {
                    apply_dir_entries(st, res);
                }
            }
            self.dirty = true;
        }
    }

    /// Run a group operation on a worker thread. `op` is an id/kind pair carried in
    /// `Event::GroupOpDone`, so the UI can match the result to the modal that started it and ignore
    /// stale completions after the user has moved on.
    fn spawn_group_op<F>(&mut self, op: GroupOp, f: F)
    where
        F: FnOnce(Arc<Core>) -> Result<String> + Send + 'static,
    {
        let id = self.next_group_op_id;
        self.next_group_op_id = self.next_group_op_id.wrapping_add(1);
        self.pending_group_op = Some((id, op.clone()));
        let core = self.core.clone();
        std::thread::spawn(move || {
            let (ok, message) = match f(core.clone()) {
                Ok(m) => (true, m),
                Err(e) => (false, format!("{e:#}")),
            };
            core.emit(Event::GroupOpDone { id, op, ok, message });
        });
    }

    /// Apply a finished background group operation to the current UI state.
    fn handle_group_op_done(&mut self, op: GroupOp, ok: bool, message: String) {
        match op {
            GroupOp::CreateGroup => {
                let modal_matches = matches!(self.modal, Some(Modal::CreateGroup { .. }));
                if ok {
                    if modal_matches { self.modal = None; }
                    self.group_names.clear();
                    self.rebuild_tree();
                    self.set_toast(message);
                } else if modal_matches {
                    if let Some(Modal::CreateGroup { msg, busy, .. }) = &mut self.modal {
                        *busy = false;
                        *msg = format!("failed to create the group: {message}");
                    }
                } else {
                    self.set_toast(format!("failed to create the group: {message}"));
                }
            }
            GroupOp::JoinGroup => {
                let modal_matches = matches!(self.modal, Some(Modal::JoinGroup { .. }));
                if ok {
                    if modal_matches { self.modal = None; }
                    self.set_toast(message);
                } else if modal_matches {
                    if let Some(Modal::JoinGroup { msg, busy, .. }) = &mut self.modal {
                        *busy = false;
                        *msg = format!("failed to submit the request: {message}");
                    }
                } else {
                    self.set_toast(format!("failed to submit the join request: {message}"));
                }
            }
            GroupOp::RenameGroup => {
                let modal_matches = matches!(self.modal, Some(Modal::RenameGroup { .. }));
                if ok {
                    if modal_matches { self.modal = None; }
                    self.group_names.clear();
                    self.rebuild_tree();
                    self.set_toast(message);
                } else if modal_matches {
                    if let Some(Modal::RenameGroup { msg, .. }) = &mut self.modal {
                        *msg = format!("rename failed: {message}");
                    }
                } else {
                    self.set_toast(format!("rename failed: {message}"));
                }
            }
            GroupOp::LeaveGroup { sid, gid } => {
                // Match the old synchronous behavior: clear local state even if the server notification
                // failed, otherwise the user stays stuck in an un-leavable group.
                if !ok {
                    let _ = self.store.delete_group(&sid, &gid);
                }
                let was_current = self.group_target.as_deref() == Some(gid.as_str());
                self.group_names.clear();
                self.drafts.retain(|(s2, c2), _| !(s2 == &sid && c2 == &gid));
                if was_current {
                    self.group_target = None;
                    self.input.clear();
                    self.input_cursor = 0;
                    self.input_scroll = 0;
                    self.clear_chat_view();
                }
                self.rebuild_tree();
                self.set_toast(if ok {
                    message
                } else {
                    format!("left the group locally (notifying the server failed: {message})")
                });
            }
            GroupOp::TransferOwner { nick, .. } => {
                if matches!(self.modal, Some(Modal::Confirm { .. })) {
                    self.modal = None;
                }
                self.set_toast(if ok {
                    message
                } else {
                    format!("failed to start the transfer to {nick}: {message}")
                });
            }
            GroupOp::DissolveGroup { sid, gid } => {
                if matches!(self.modal, Some(Modal::Confirm { .. })) {
                    self.modal = None;
                }
                if ok {
                    let was_current = self.group_target.as_deref() == Some(gid.as_str());
                    self.group_names.clear();
                    if was_current {
                        self.group_target = None;
                        self.input.clear();
                        self.input_cursor = 0;
                        self.input_scroll = 0;
                        self.clear_chat_view();
                    }
                    self.rebuild_tree();
                    self.set_toast(message);
                } else {
                    self.set_toast(format!("failed to dissolve group {gid}: {message}"));
                }
                let _ = sid;
            }
            GroupOp::KickMember { nick, .. } => {
                if matches!(self.modal, Some(Modal::Confirm { .. })) {
                    self.modal = None;
                }
                if ok {
                    self.group_names.clear();
                    self.rebuild_tree();
                }
                self.set_toast(if ok {
                    message
                } else {
                    format!("failed to remove {nick}: {message}")
                });
            }
            GroupOp::Notice => {
                self.set_toast(message);
            }
        }
    }

    fn send_input(&mut self) {
        if self.input.trim().is_empty() { return; }
        // Group chat: encrypt locally with MLS first, then hand it to the server's group queue
        if let Some(gid) = self.group_target.clone() {
            let Some(sid) = self.core.cur_server() else { return };
            let text = self.input.clone();
            match crate::group::runtime::service_for(&self.core, &sid)
                .and_then(|svc| svc.send_text(&gid, &text))
            {
                Ok(_seq) => {
                    // No toast: the bubble itself is the best feedback (the 1v1 send path does the same)
                    self.input.clear();
                    self.input_cursor = 0;
                    self.input_scroll = 0;
                    self.save_draft();
                    self.reload_chat();
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("EPOCH_MISMATCH") {
                        // The group key just rotated (e.g. a removal commit added after an owner transfer) and we
                        // are still on the old epoch: schedule a sync to merge the new commits, then ask for a
                        self.sync_after_epoch_rotation(&sid, &gid);
                        self.set_toast("the group key just rotated; syncing, retry in a moment".to_string());
                    } else {
                        self.set_toast(format!("failed to send the group message: {msg}"));
                    }
                }
            }
            return;
        }
        match self.core.send_text(&self.input) {
            Ok(()) => {
                if let Some(k) = self.draft_key() { self.drafts.remove(&k); }
                self.input.clear();
                self.input_cursor = 0;
                self.input_scroll = 0;
                self.reload_chat();
            }
            Err(e) => self.set_toast(format!("send failed: {e:#}")),
        }
    }

    /// Visible chat-area line count (must match `content_h` in draw)
    fn chat_visible_lines(&self) -> usize {
        let h = self.last_size.1;
        let input_top = h.saturating_sub(INPUT_BOX_H);
        let chat_h = input_top.saturating_sub(2) + 1;
        (chat_h.saturating_sub(2) as usize).max(1)
    }

    fn chat_page(&mut self, dir: i32) {
        let vis = self.chat_visible_lines();
        let page = vis.saturating_sub(1).max(1);
        if dir < 0 {
            // At the top: lazily load EARLIER_MSGS more
            if self.chat_scroll + page >= self.max_chat_scroll() {
                if let (Some(sid), Some(contact), Some(first)) =
                    (self.core.cur_server(), self.core.cur_contact(),
                     self.messages.first().map(|m| m.id))
                {
                    if self.chat_total > self.messages.len() as i64 {
                        // No more `if let Ok(..)` swallowing errors: report a failed earlier-page load instead of a silent PgUp.
                        match self.core.load_earlier(&sid, &contact, first, EARLIER_MSGS) {
                            Ok(rows) if !rows.is_empty() => {
                                // chat_scroll counts render lines: add the new lines measured at the current width to keep the viewport still
                                let inner_w = (self.chat_lines_w as usize).max(10);
                                let me = self.core.cur_server()
                                    .and_then(|s| self.core.username_of(&s)).unwrap_or_default();
                                let added_lines: usize = rows.iter()
                                    .map(|m| self.message_lines(m, inner_w, &me).len())
                                    .sum();
                                let mut new = rows;
                                new.extend(std::mem::take(&mut self.messages));
                                self.messages = new;
                                self.rebuild_chat_lines(inner_w);
                                self.chat_scroll += added_lines;
                            }
                            Ok(_) => {}
                            Err(e) => self.set_toast(format!("failed to load earlier messages: {e:#}")),
                        }
                    }
                }
            }
            self.chat_scroll = (self.chat_scroll + page).min(self.max_chat_scroll());
        } else {
            self.chat_scroll = self.chat_scroll.saturating_sub(page);
        }
    }

    fn max_chat_scroll(&self) -> usize {
        self.chat_lines_count().saturating_sub(self.chat_visible_lines())
    }
    fn chat_lines_count(&self) -> usize { self.chat_lines.len() }

    // ---------------- layout helpers ----------------

    fn sidebar_width(&self) -> u16 {
        let w = self.last_size.0;
        // Clamp floor is 35: times 0.81 that is 28, the minimum width for the two-column button grid
        // (see `build_button_grid`: at width 28 the right column fits the longest F-key label).
        let mut sw = ((w as f32 * 0.34) as u16).clamp(35, 38);
        sw = ((sw as f32 * 0.81) as u16).max(28);
        sw.min(w.saturating_sub(32))
    }

    // ---------------- modal keys ----------------
    fn handle_modal_key(&mut self, k: KeyEvent) {
        let mut close = false;
        // File picker: Enter/Backspace must wait until the immutable borrow ends before loading a directory or sending
        let mut picker_enter: Option<PathBuf> = None;
        let mut picker_send: Option<PathBuf> = None;
        // `self.modal` is mutably borrowed, so a toast has to be deferred until after the match
        let mut deferred_toast: Option<String> = None;
        // `match self.modal.as_mut()` cannot replace the modal (double borrow), so defer applying it
        let mut next_modal: Option<Modal> = None;
        // Group operations must not run on the TUI thread; the closure is deferred until the modal
        // borrow ends and then handed to `spawn_group_op`.
        let mut deferred_group_op: Option<(
            GroupOp,
            Box<dyn FnOnce(Arc<Core>) -> Result<String> + Send + 'static>,
        )> = None;
        // Read before the `self.modal` mutable borrow: a second Enter while an async group operation
        // is in flight must not enqueue a duplicate.
        let group_op_inflight = self.pending_group_op.is_some();
        match self.modal.as_mut() {
            Some(Modal::Help) => {
                if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char(' ')) { close = true; }
            }
            Some(Modal::Confirm { action, .. }) => {
                let a = action.clone();
                match k.code {
                    // Enter and y are equivalent: the modal is already an explicit confirmation (the user pressed d or picked delete), so demanding y only looks broken.
                    KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                        match a {
                            ConfirmAction::DeleteServer(sid) => {
                                match self.core.delete_server(&sid) {
                                    Ok(()) => {
                                        self.set_toast("server and its local data deleted");
                                        // After deleting the server holding the current session, the "no server selected" view must not keep showing its chat.
                                        if self.core.cur_server().is_none() {
                                            self.clear_chat_view();
                                        }
                                    }
                                    Err(e) => self.set_toast(format!("failed to delete the server: {e:#}")),
                                }
                            }
                            ConfirmAction::DeleteContact(sid, c) => {
                                // Must be decided before deleting: `delete_contact` clears `current_contact`, so the comparison is false afterwards and the messages linger in the chat area.
                                let was_current =
                                    self.core.cur_server().as_deref() == Some(sid.as_str())
                                    && self.core.cur_contact().as_deref() == Some(c.as_str());
                                match self.core.delete_contact(&sid, &c) {
                                    Ok(()) => {
                                        self.drafts.remove(&(sid.clone(), c.clone()));
                                        if was_current {
                                            self.input.clear();
                                            self.input_cursor = 0;
                                            self.input_scroll = 0;
                                            self.clear_chat_view();
                                        }
                                        self.set_toast(format!("contact {c} and its chat history deleted"));
                                    }
                                    Err(e) => self.set_toast(format!("failed to delete the contact: {e:#}")),
                                }
                            }
                            ConfirmAction::LeaveGroup(sid, gid, successor) => {
                                let op_sid = sid.clone();
                                let op_gid = gid.clone();
                                deferred_group_op = Some((
                                    GroupOp::LeaveGroup { sid: op_sid.clone(), gid: op_gid.clone() },
                                    Box::new(move |core| {
                                        crate::group::runtime::service_for(&core, &op_sid)
                                            .and_then(|svc| svc.leave_group(&op_gid, successor.as_deref()))?;
                                        Ok("left the group (the other members will remove you from the member list when they sync)".to_string())
                                    }),
                                ));
                            }
                            ConfirmAction::TransferOwner(sid, gid, uid, nick) => {
                                let op_sid = sid.clone();
                                let op_gid = gid.clone();
                                let op_uid = uid.clone();
                                let op_nick = nick.clone();
                                deferred_group_op = Some((
                                    GroupOp::TransferOwner {
                                        sid: op_sid.clone(), gid: op_gid.clone(), nick: op_nick.clone(),
                                    },
                                    Box::new(move |core| {
                                        crate::group::runtime::service_for(&core, &op_sid)
                                            .and_then(|svc| svc.start_owner_transfer(&op_gid, &op_uid))?;
                                        Ok(format!(
                                            "owner transfer to {op_nick} started; they must confirm it in the notice list (F7)"
                                        ))
                                    }),
                                ));
                            }
                            ConfirmAction::DissolveGroup(sid, gid) => {
                                let op_sid = sid.clone();
                                let op_gid = gid.clone();
                                deferred_group_op = Some((
                                    GroupOp::DissolveGroup { sid: op_sid.clone(), gid: op_gid.clone() },
                                    Box::new(move |core| {
                                        crate::group::runtime::service_for(&core, &op_sid)
                                            .and_then(|svc| svc.dissolve_group(&op_gid))?;
                                        Ok("group dissolved".to_string())
                                    }),
                                ));
                            }
                            ConfirmAction::KickMember(sid, gid, uid, nick) => {
                                let op_sid = sid.clone();
                                let op_gid = gid.clone();
                                let op_uid = uid.clone();
                                let op_nick = nick.clone();
                                deferred_group_op = Some((
                                    GroupOp::KickMember {
                                        sid: op_sid.clone(), gid: op_gid.clone(), nick: op_nick.clone(),
                                    },
                                    Box::new(move |core| {
                                        let ep = crate::group::runtime::service_for(&core, &op_sid)
                                            .and_then(|svc| svc.remove_member(&op_gid, &op_uid))?;
                                        Ok(format!("removed {op_nick} (epoch {ep}, keys rotated)"))
                                    }),
                                ));
                            }
                            // B5: confirm quit (may interrupt downloads in flight; chunks are kept for resume)
                            ConfirmAction::Quit => {
                                self.running = false;
                            }
                        }
                        close = true;
                    }
                    KeyCode::Char('n') | KeyCode::Esc => close = true,
                    _ => {}
                }
            }
            Some(Modal::RenameGroup { sid, gid, field, msg }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Backspace => {
                        field.pop();
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        field.push(c)
                    }
                    KeyCode::Enter => {
                        let name = field.trim().to_string();
                        if name.is_empty() {
                            *msg = "the group name cannot be empty".into();
                        } else if group_op_inflight {
                            *msg = "another group operation is still in progress".into();
                        } else {
                            let op_sid = sid.clone();
                            let op_gid = gid.clone();
                            let op_name = name.clone();
                            deferred_group_op = Some((
                                GroupOp::RenameGroup,
                                Box::new(move |core| {
                                    let ep = crate::group::runtime::service_for(&core, &op_sid)
                                        .and_then(|svc| svc.set_group_name(&op_gid, &op_name))?;
                                    Ok(format!(
                                        "group name changed to '{op_name}' (epoch {ep}, broadcast to the whole group)"
                                    ))
                                }),
                            ));
                            *msg = "renaming broadcasts one MLS commit...".into();
                        }
                    }
                    _ => {}
                }
            }
            Some(Modal::RenameContact { sid, contact, field }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Enter => {
                        let sid = sid.clone();
                        let contact = contact.clone();
                        let name = field.trim().to_string();
                        match self.core.rename_contact(&sid, &contact, &name) {
                            Ok(()) => {
                                let show = if name.is_empty() { contact.clone() } else { name.clone() };
                                self.set_toast(format!("contact renamed to {show}"));
                            }
                            Err(e) => self.set_toast(format!("rename failed: {e:#}")),
                        }
                        close = true;
                    }
                    KeyCode::Backspace => { field.pop(); }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => field.push(c),
                    _ => {}
                }
            }
            Some(Modal::RenameServer { sid, field }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Enter => {
                        let sid = sid.clone();
                        let name = field.trim().to_string();
                        match self.core.rename_server(&sid, &name) {
                            Ok(()) => self.set_toast(format!("server renamed to {name}")),
                            Err(e) => self.set_toast(format!("rename failed: {e:#}")),
                        }
                        close = true;
                    }
                    KeyCode::Backspace => { field.pop(); }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => field.push(c),
                    _ => {}
                }
            }
            Some(Modal::CreateGroup { name, nick, focus, msg, busy }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Tab | KeyCode::Up | KeyCode::Down => {
                        *focus = if *focus == 0 { 1 } else { 0 };
                    }
                    KeyCode::Enter if !*busy => {
                        let gname = name.trim().to_string();
                        let my_nick = nick.trim().to_string();
                        if gname.is_empty() {
                            *msg = "the group name cannot be empty".into();
                        } else if my_nick.is_empty() {
                            // The nickname is required: it goes into the MLS credential and decides the "message source" others see; empty means other members only see a user_id.
                            *msg = "enter your nickname in the group (required)".into();
                            *focus = 1;
                        } else if group_op_inflight {
                            *msg = "another group operation is still in progress".into();
                        } else if let Some(sid) = self.core.cur_server() {
                            let op_sid = sid.clone();
                            deferred_group_op = Some((
                                GroupOp::CreateGroup,
                                Box::new(move |core| {
                                    let st = crate::group::runtime::service_for(&core, &op_sid)
                                        .and_then(|svc| svc.create_group(&gname, &my_nick))?;
                                    Ok(format!(
                                        "group {} created (send the group ID to others so they can join)",
                                        st.group_id
                                    ))
                                }),
                            ));
                            *busy = true;
                            *msg = "creating the group...".into();
                        } else {
                            *msg = "select a server first".into();
                        }
                    }
                    KeyCode::Backspace => {
                        if *focus == 0 { name.pop(); } else { nick.pop(); }
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if *focus == 0 { name.push(c); } else { nick.push(c); }
                    }
                    _ => {}
                }
            }
            Some(Modal::JoinGroup { gid, text, nick, focus, msg, busy }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Tab | KeyCode::Down => { *focus = (*focus + 1) % 3; }
                    KeyCode::Up => { *focus = (*focus + 2) % 3; }
                    KeyCode::Enter if !*busy => {
                        let g = gid.trim().to_string();
                        let t = text.trim().to_string();
                        let my_nick = nick.trim().to_string();
                        if g.is_empty() {
                            *msg = "the group ID cannot be empty".into();
                        } else if my_nick.is_empty() {
                            *msg = "enter your nickname in the group (required)".into();
                            *focus = 2;
                        } else if t.is_empty() {
                            *msg = "enter a join request note (required)".into();
                            *focus = 1;
                        } else if group_op_inflight {
                            *msg = "another group operation is still in progress".into();
                        } else if let Some(sid) = self.core.cur_server() {
                            let op_sid = sid.clone();
                            deferred_group_op = Some((
                                GroupOp::JoinGroup,
                                Box::new(move |core| {
                                    let p = crate::group::runtime::service_for(&core, &op_sid)
                                        .and_then(|svc| svc.request_join(&g, &t, &my_nick))?;
                                    Ok(format!(
                                        "request {} submitted; waiting for the owner's approval",
                                        p.request_id
                                    ))
                                }),
                            ));
                            *busy = true;
                            *msg = "submitting the join request...".into();
                        } else {
                            *msg = "select a server first".into();
                        }
                    }
                    KeyCode::Backspace => match *focus {
                        0 => { gid.pop(); }
                        1 => { text.pop(); }
                        _ => { nick.pop(); }
                    },
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => match *focus {
                        0 => gid.push(c),
                        1 => text.push(c),
                        _ => nick.push(c),
                    },
                    _ => {}
                }
            }
            Some(Modal::PickSuccessor { sid, gid, rows, sel, for_leave }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Up => { *sel = sel.saturating_sub(1); }
                    KeyCode::Down => {
                        if *sel + 1 < rows.len() { *sel += 1; }
                    }
                    KeyCode::Enter => {
                        if let Some((nick, uid)) = rows.get(*sel) {
                            let leave = *for_leave;
                            next_modal = Some(Modal::Confirm {
                                title: if leave { " Leave group ".into() } else { " Transfer ownership ".into() },
                                text: if leave {
                                    format!(
                                        "Transfer ownership to {nick} and leave the group?\n\n\
                                         · they must **confirm** in the notice list (F7) to take over;\n\
                                         · until they confirm, nobody can join this group."
                                    )
                                } else {
                                    format!(
                                        "Transfer ownership to {nick}?\n\n\
                                         · they must **confirm** it in the notice list (F7);\n\
                                         · until then you still own the group and approve joins;\n\
                                         · joins are unaffected meanwhile."
                                    )
                                },
                                action: if leave {
                                    ConfirmAction::LeaveGroup(
                                        sid.clone(),
                                        gid.clone(),
                                        Some(uid.clone()),
                                    )
                                } else {
                                    ConfirmAction::TransferOwner(
                                        sid.clone(),
                                        gid.clone(),
                                        uid.clone(),
                                        nick.clone(),
                                    )
                                },
                            });
                        }
                    }
                    _ => {}
                }
            }
            Some(Modal::Notices { rows, sel, expanded, msg }) => {
                let flat = notice_flat(rows, expanded);
                if *sel >= flat.len() {
                    *sel = flat.len().saturating_sub(1);
                }
                let cur = flat.get(*sel).copied();
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Up => *sel = sel.saturating_sub(1),
                    KeyCode::Down => {
                        if *sel + 1 < flat.len() {
                            *sel += 1;
                        }
                    }
                    // Space: expand/collapse the current category (header and item rows both act on their category)
                    KeyCode::Char(' ') => {
                        if let Some((cat, _)) = cur {
                            expanded[cat] = !expanded[cat];
                        }
                    }
                    KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('n') => {
                        let accept = !matches!(k.code, KeyCode::Char('n'));
                        if let Some((cat, item)) = cur {
                            let Some(idx) = item else {
                                // On a category header the accept key is equivalent to expand/collapse
                                expanded[cat] = !expanded[cat];
                                return;
                            };
                            let n = rows[idx].clone();
                            let sid = n.sid.clone();
                            match &n.action {
                                // MLS approval/transfer can involve several signed HTTPS round-trips; run it off the TUI thread.
                                NoticeAction::JoinRequest { .. } | NoticeAction::OwnerTransfer { .. } => {
                                    let action = n.action.clone();
                                    let op_sid = sid.clone();
                                    deferred_group_op = Some((
                                        GroupOp::Notice,
                                        Box::new(move |core| {
                                            let svc = crate::group::runtime::service_for(&core, &op_sid)?;
                                            match (&action, accept) {
                                                (NoticeAction::JoinRequest { gid, request_id }, true) => svc
                                                    .approve_and_add(gid, request_id)
                                                    .map(|(ep, u)| format!("approved {u} (epoch {ep})")),
                                                (NoticeAction::JoinRequest { gid, request_id }, false) => svc
                                                    .decide_join_request(gid, request_id, false)
                                                    .map(|_| "request rejected".to_string()),
                                                (NoticeAction::OwnerTransfer { gid }, true) => svc
                                                    .decide_owner_transfer(gid, true)
                                                    .map(|_| "owner transfer accepted".to_string()),
                                                (NoticeAction::OwnerTransfer { gid }, false) => svc
                                                    .decide_owner_transfer(gid, false)
                                                    .map(|_| "owner transfer rejected".to_string()),
                                                _ => Ok("operation completed".to_string()),
                                            }
                                        }),
                                    ));
                                    *msg = "processing...".into();
                                }
                                // Friend request: confirm runs the existing "add contact by ID" flow (already backgrounded).
                                NoticeAction::FriendRequest { peer } if accept => {
                                    self.core.add_contact_on(
                                        &sid,
                                        peer.clone(),
                                        String::new(),
                                        crate::crypto::generate_msg_id(),
                                    );
                                    *msg = format!("add request sent: {peer}");
                                }
                                NoticeAction::FriendRequest { peer } => {
                                    *msg = format!("ignored the request from {peer}");
                                }
                                NoticeAction::Dismiss => {
                                    *msg = "dismissed".into();
                                    self.system_notices.retain(|t| t != &n.label);
                                }
                            }
                            rows.remove(idx);
                            *sel = sel.saturating_sub(1);
                        }
                    }
                    _ => {}
                }
            }
            Some(Modal::GroupMembers { sid, gid, rows, sel }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Up => { *sel = sel.saturating_sub(1); }
                    KeyCode::Down => {
                        if *sel + 1 < rows.len() { *sel += 1; }
                    }
                    // `d` / Del: remove the selected member (the server re-validates owner/admin); the modal cannot be replaced while borrowed, so defer until it closes.
                    KeyCode::Char('d') | KeyCode::Delete => {
                        if let Some((nick, uid, _role)) = rows.get(*sel) {
                            next_modal = Some(Modal::Confirm {
                                title: " Remove member ".into(),
                                text: format!(
                                    "Remove {nick} from this group?\n\n                                     · one MLS commit is broadcast (advancing the epoch and rotating keys);\n                                     · they **can no longer decrypt new messages in this group**;\n                                     · their client discovers the removal on its next sync."
                                ),
                                action: ConfirmAction::KickMember(
                                    sid.clone(),
                                    gid.clone(),
                                    uid.clone(),
                                    nick.clone(),
                                ),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Some(Modal::FilePicker(st)) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Up => { st.sel = st.sel.saturating_sub(1); st.ensure_visible(); }
                    KeyCode::Down => {
                        if st.sel + 1 < st.entries.len() { st.sel += 1; }
                        st.ensure_visible();
                    }
                    KeyCode::PageUp => {
                        st.sel = st.sel.saturating_sub(FILE_PICKER_VIS); st.ensure_visible();
                    }
                    KeyCode::PageDown => {
                        st.sel = (st.sel + FILE_PICKER_VIS).min(st.entries.len().saturating_sub(1));
                        st.ensure_visible();
                    }
                    KeyCode::Home => { st.sel = 0; st.ensure_visible(); }
                    KeyCode::End => {
                        st.sel = st.entries.len().saturating_sub(1); st.ensure_visible();
                    }
                    KeyCode::Enter => {
                        if let Some(e) = st.entries.get(st.sel) {
                            if e.is_dir { picker_enter = Some(e.path.clone()); }
                            else { picker_send = Some(e.path.clone()); }
                        }
                    }
                    KeyCode::Backspace => {
                        if let Some(parent) = st.cwd.parent() {
                            picker_enter = Some(parent.to_path_buf());
                        }
                    }
                    _ => {}
                }
            }
            Some(Modal::AddContact { id_field, name_field, focus, msg, req, sent }) => {
                match k.code {
                    KeyCode::Esc => close = true,
                    KeyCode::Tab | KeyCode::Down => *focus = (*focus + 1) % 2,
                    KeyCode::Up | KeyCode::BackTab => *focus = (*focus + 1) % 2,
                    KeyCode::Enter => {
                        // Enter always submits (as in the server form); Tab/Up/Down switch fields.
                        if !*sent && !id_field.trim().is_empty() {
                            let id = id_field.trim().to_string();
                            let name = name_field.trim().to_string();
                            *msg = "querying the server...".into();
                            let reqid = format!("req{}", crate::crypto::chrono_now_ms());
                            *req = Some(reqid.clone());
                            *sent = true;
                            self.core.add_contact(id, name, reqid);
                        } else if id_field.trim().is_empty() {
                            *msg = "the contact ID cannot be empty".into();
                        }
                    }
                    KeyCode::Backspace => {
                        if *focus == 0 { id_field.pop(); } else { name_field.pop(); }
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if *focus == 0 { id_field.push(c); } else { name_field.push(c); }
                    }
                    _ => {}
                }
            }
            Some(Modal::ServerList { sel, form }) => {
                if let Some(f) = form.as_mut() {
                    match k.code {
                        KeyCode::Esc => { *form = None; }
                        KeyCode::Tab | KeyCode::Down => f.focus = (f.focus + 1) % 3,
                        KeyCode::Up => f.focus = (f.focus + 2) % 3,
                        KeyCode::Enter => {
                            if f.focus < 2 { f.focus += 1; }
                            else if !f.host.trim().is_empty()
                                && f.port.trim().parse::<i64>()
                                    .map(|p| (store::PORT_MIN..=store::PORT_MAX).contains(&p))
                                    .unwrap_or(false)
                            {
                                // Save = write DB + create session + connect immediately (no restart)
                                let port: i64 = f.port.trim().parse().unwrap();
                                deferred_toast = Some(
                                    match self.core.add_server(&f.name, f.host.trim(), port) {
                                        Ok(_) => format!("server {}:{} added, connecting...",
                                                         f.host.trim(), port),
                                        Err(e) => format!("failed to add the server: {e:#}"),
                                    });
                                *form = None;
                            } else if !f.host.trim().is_empty() {
                                // Report an invalid port in place instead of doing nothing (old behavior) or silently truncating 99999 to 34463 and dialing the wrong port.
                                deferred_toast = Some(format!(
                                    "the port must be an integer between {}..{} (current: {})",
                                    store::PORT_MIN, store::PORT_MAX, f.port.trim()));
                            }
                        }
                        KeyCode::Backspace => {
                            let s = match f.focus { 0 => &mut f.name, 1 => &mut f.host, _ => &mut f.port };
                            s.pop();
                        }
                        KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                            let s = match f.focus { 0 => &mut f.name, 1 => &mut f.host, _ => &mut f.port };
                            s.push(c);
                        }
                        _ => {}
                    }
                } else {
                    let order = self.core.live_order();
                    let n = order.len();
                    match k.code {
                        KeyCode::Esc | KeyCode::Char('q') => close = true,
                        KeyCode::Up => *sel = sel.saturating_sub(1),
                        KeyCode::Down => { if n > 0 { *sel = (*sel + 1).min(n - 1); } }
                        KeyCode::Enter => {
                            if let Some(sid) = order.get(*sel).cloned() {
                                self.core.connect_one(sid);
                                self.set_toast("connecting...");
                            }
                        }
                        KeyCode::Char('a') => {
                            *form = Some(AddForm { name: String::new(), host: String::new(),
                                                   port: "60345".into(), focus: 1 })
                        }
                        // Terminal-independent quit entry: capital `Q` (lowercase q already closes modals) is plain ASCII that any terminal can send;
                        // some terminals (Xshell, ...) never deliver Ctrl+Alt+M.
                        KeyCode::Char('Q') => {
                            next_modal = Some(Modal::Confirm {
                                title: " Confirm quit ".into(),
                                text: "Quit the client?\n\nDrafts and unread state stay in the local database.".to_string(),
                                action: ConfirmAction::Quit,
                            });
                        }
                        KeyCode::Char('c') => self.core.connect_all(),
                        _ => {}
                    }
                }
            }
            None => {}
        }
        if let Some(dir) = picker_enter {
            if let Some(Modal::FilePicker(st)) = &mut self.modal {
                st.loading = true;
                st.requested = dir.clone();
            }
            self.request_dir_load(dir);
        }
        if let Some(path) = picker_send {
            self.modal = None;
            self.core.send_file(path);
        }
        if close {
            self.modal = None;
        }
        // Apply the deferred modal after the borrow ends (F9 -> d opens the "remove member" confirmation).
        // Group operations rebuild the tree from their `GroupOpDone` event handler instead.
        if let Some(m) = next_modal {
            self.modal = Some(m);
        }
        if let Some(t) = deferred_toast {
            self.set_toast(t);
        }
        if let Some((op, task)) = deferred_group_op {
            self.spawn_group_op(op, task);
        }
    }

    // ---------------- drawing ----------------
    fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        if area.width < 64 || area.height < 22 {
            let msg = Paragraph::new(format!("terminal window too small; resize to at least 64x22 (current {}x{})",
                area.width, area.height));
            f.render_widget(msg, area);
            return;
        }
        let sw = self.sidebar_width();
        let rx = sw + 1;
        let rw = area.width - rx - 1;
        let input_top = area.height.saturating_sub(INPUT_BOX_H);
        let chat_h = input_top.saturating_sub(2) + 1;

        let chat_inner_w = rw.saturating_sub(4);
        if self.chat_dirty || self.chat_lines_w != chat_inner_w {
            self.rebuild_chat_lines(chat_inner_w as usize);
        }
        self.draw_sidebar(f, area, sw);
        self.ensure_input_cursor_visible();
        self.draw_right(f, area, rx, rw, chat_h, input_top);
        if let Some(m) = &self.modal {
            self.draw_modal(f, area, m);
        }
        self.draw_toast(f, area, rx, rw, chat_h);
        // Caret placement priority: 1) modal text input (else no caret while typing) 2) main input box.
        // Columns always use **display width** (CJK/full-width occupy 2), or the caret lands inside a character.
        // Modal content renders at `x+2` and a value row is "[ " + text + " ]", so text starts at `x+4`.
        let content_w = rw.saturating_sub(4) as usize;
        if let Some((field, line_idx)) = self.modal_text_caret() {
            let modal_w = self.modal.as_ref().map(modal_width).unwrap_or(60);
            f.set_cursor_position(modal_caret_pos(
                area, modal_w, self.modal_line_count(), line_idx, field, content_w));
        } else if self.focus == Focus::Input {
            let (line, _) = self.input_cursor_line_col();
            let row = line.saturating_sub(self.input_scroll)
                .min(INPUT_CONTENT_LINES.saturating_sub(1));
            let disp_col = self.input_cursor_display_col();
            let cx = rx as usize + 2 + disp_col.min(content_w);
            f.set_cursor_position((cx as u16, input_top + 1 + row as u16));
        }
    }

    /// The text field the current modal edits -> `(field text, row of the value line inside the modal)`; None for non-text modals.
    /// Row numbers must match the push order in `draw_modal` (guarded by `modal_caret_layout_is_self_consistent`).
    /// **Width comes solely from `modal_width`**; a second local constant once drifted and misaligned the caret.
    fn modal_text_caret(&self) -> Option<(&str, usize)> {
        match &self.modal {
            // Row order: 0 server / 1 blank / 2 contact-ID label / 3 [ID] / 4 blank / 5 optional display-name label /
            //       6 [name] / 7 blank / 8 hint
            Some(Modal::AddContact { id_field, name_field, focus, .. }) => Some(if *focus == 0 {
                (id_field.as_str(), 3)
            } else {
                (name_field.as_str(), 6)
            }),
            // Row order: 0 description / 1 blank / 2 [value] / 3 blank / 4 hint
            Some(Modal::RenameServer { field, .. }) => Some((field.as_str(), 2)),
            // Row order: 0 group-name hint / 1 [group name] / 2 nickname hint / 3 [nickname] / ...
            Some(Modal::CreateGroup { name, nick, focus, .. }) => Some(if *focus == 0 {
                (name.as_str(), 2)
            } else {
                (nick.as_str(), 4)
            }),
            // Row order: 0 ID hint / 1 [group ID] / 2 hint / 3 [note] / 4 nickname hint / 5 [nickname] / ...
            Some(Modal::JoinGroup { gid, text, nick, focus, .. }) => Some(match *focus {
                0 => (gid.as_str(), 2),
                1 => (text.as_str(), 4),
                _ => (nick.as_str(), 6),
            }),
            // Row order: 0 contact / 1 "display name (optional)" / 2 blank / 3 [value] / 4 blank / 5 hint
            Some(Modal::RenameContact { field, .. }) => Some((field.as_str(), 3)),
            // Row order: 0 group ID / 1 hint / 2 blank / 3 [group name] / 4 blank / 5 hint
            Some(Modal::RenameGroup { field, .. }) => Some((field.as_str(), 3)),
            _ => None,
        }
    }

    /// Modal content line count (for vertical centering; must match `lines.len()` in `draw_modal`).
    fn modal_line_count(&self) -> u16 {
        modal_line_count(&self.modal)
    }

    fn draw_sidebar(&mut self, f: &mut Frame, area: Rect, sw: u16) {
        for y in 0..area.height {
            f.render_widget(Paragraph::new("│"), Rect::new(sw, y, 1, 1));
        }
        // Button area (2 columns x 5 rows); the test is "any count > 0", not "map non-empty": the startup rescan fires an event for every group I manage, including 0.
        let has_pending = self.pending_approvals.values().any(|n| *n > 0);
        let lines = build_button_grid(sw as usize, has_pending);
        let btn_h = lines.len() as u16;
        f.render_widget(Paragraph::new(lines), Rect::new(0, 0, sw, btn_h));

        let tree_top = 9u16;
        let tree_h = area.height.saturating_sub(tree_top + 1);
        let title = format!("Servers ({})", self.core.live_order().len());
        let block = Block::default().borders(Borders::ALL)
            .title(format!(" {title} "))
            .style(Style::default().fg(Color::Yellow));
        let inner = Rect::new(0, tree_top, sw, tree_h);
        f.render_widget(block.clone(), inner);
        let list_area = Rect::new(1, tree_top + 1, sw.saturating_sub(2), tree_h.saturating_sub(2));

        let vis = list_area.height as usize;
        if self.sel < self.tree_scroll { self.tree_scroll = self.sel; }
        if vis > 0 && self.sel >= self.tree_scroll + vis {
            self.tree_scroll = self.sel + 1 - vis;
        }
        let mut tlines: Vec<Line> = Vec::new();
        let inner_w = list_area.width as usize;
        for (i, it) in self.items.iter().enumerate().skip(self.tree_scroll).take(vis) {
            let is_server = it.kind == TreeKind::Server;
            let selected = i == self.sel;

            // Server v/> (color = connectivity); contact o (color = online);
            // group [] fixed color, **not an online indicator** (groups have no online concept).
            let (mark, mark_color, mark_w) = if is_server {
                (if it.expanded { "▼" } else { "▶" },
                 if it.online { Color::Green } else { Color::Red }, 1)
            } else if it.kind == TreeKind::Group {
                ("▣", GROUP_ICON_COLOR, 1)
            } else {
                ("●", if it.online { Color::Green } else { Color::Red }, 1)
            };

            // Indent: servers flush left, contacts indented 3 columns (matches the Python version)
            let indent = if is_server { "" } else { "   " };
            let gap = if is_server { "" } else { " " };

            let mut label = it.label.clone();
            if it.unread > 0 {
                label = format!("{label} ({})", it.unread);
            }
            let used = disp_width(indent) + mark_w + disp_width(gap);
            let avail = inner_w.saturating_sub(used);
            label = truncate(&label, avail);
            let pad = avail.saturating_sub(disp_width(&label));
            let name = format!("{label}{}", " ".repeat(pad));
            let name_style = if selected {
                Style::default().bg(Color::Yellow).fg(Color::Black).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            tlines.push(Line::from(vec![
                Span::raw(indent),
                Span::styled(mark, Style::default().fg(mark_color)),
                Span::raw(gap),
                Span::styled(name, name_style),
            ]));
        }
        f.render_widget(Paragraph::new(tlines), list_area);

        let id_line = format!("me:{}", self.client_id());
        f.render_widget(
            Paragraph::new(id_line).style(Style::default().add_modifier(Modifier::UNDERLINED)),
            Rect::new(1, area.height - 1, sw.saturating_sub(2), 1));
    }

    fn draw_right(&mut self, f: &mut Frame, _area: Rect, rx: u16, rw: u16, chat_h: u16, input_top: u16) {
        let server_name = self.core.cur_server()
            .and_then(|sid| self.core.session(&sid))
            .map(|s| s.name()).unwrap_or_else(|| "no server selected".into());
        let contact = self.core.cur_contact();
        let title = if let Some(gid) = self.group_target.clone() {
            // Group chat title: `server | [group] name - group ID`; the epoch is deliberately hidden.
            let sid = self.core.cur_server().unwrap_or_default();
            let name = self
                .group_names
                .get(&format!("{sid}|{gid}"))
                .cloned()
                .unwrap_or_else(|| "group".to_string());
            format!("{server_name} | [group] {name} · {gid}")
        } else {
            match &contact {
                None => format!("{server_name} | no contact selected"),
                Some(c) => {
                    let nick = self.nick_of(&self.core.cur_server().unwrap_or_default(), c);
                    format!("{server_name} | {nick}")
                }
            }
        };
        let chat_block = Block::default().borders(Borders::ALL)
            .title(format!(" {} ", truncate(&title, rw as usize - 4)))
            .style(Style::default().fg(Color::Yellow));
        f.render_widget(chat_block, Rect::new(rx, 0, rw, chat_h));

        // Message bubbles: cached lines, only viewport slicing (no per-frame rebuild or DB query)
        let content_h = chat_h.saturating_sub(2);
        let inner_w = rw.saturating_sub(4);
        let vis = content_h as usize;
        let total = self.chat_lines.len();
        let max_scroll = total.saturating_sub(vis);
        self.chat_scroll = self.chat_scroll.min(max_scroll);
        let view: Vec<Line> = if total == 0 {
            vec![Line::from(if contact.is_none() { "select a contact to start chatting" } else { "no messages" })]
        } else {
            let end = total.saturating_sub(self.chat_scroll);
            let start = end.saturating_sub(vis);
            self.chat_lines[start..end].to_vec()
        };
        f.render_widget(Paragraph::new(view).wrap(Wrap { trim: false }),
            Rect::new(rx + 2, 1, inner_w, content_h));

        // Input box (fixed 3 content lines; Shift+Enter for newlines, scrolls when full)
        let focus_style = if self.focus == Focus::Input {
            Style::default().fg(Color::Yellow)
        } else { Style::default().fg(Color::DarkGray) };
        f.render_widget(
            Block::default().borders(Borders::ALL).title(" Message ").style(focus_style),
            Rect::new(rx, input_top, rw, INPUT_BOX_H));
        let content_w = rw.saturating_sub(4) as usize;
        let all_lines: Vec<&str> = self.input.split('\n').collect();
        let start = self.input_scroll.min(all_lines.len().saturating_sub(1));
        let end = (start + INPUT_CONTENT_LINES).min(all_lines.len());
        let text = all_lines[start..end].iter()
            .map(|l| truncate(l, content_w))
            .collect::<Vec<_>>().join("\n");
        f.render_widget(
            Paragraph::new(text),
            Rect::new(rx + 2, input_top + 1, rw.saturating_sub(4), INPUT_CONTENT_LINES as u16));
    }

    fn draw_toast(&self, f: &mut Frame, area: Rect, rx: u16, rw: u16, chat_h: u16) {
        let Some((text, at)) = &self.toast else { return };
        if at.elapsed() > Duration::from_secs(TOAST_SECS) { return; }
        let w = (disp_width(text) + 4).min(rw as usize) as u16;
        let x = rx + (rw.saturating_sub(w)) / 2;
        f.render_widget(Clear, Rect::new(x, 1, w, 1));
        f.render_widget(
            Paragraph::new(format!(" {text} "))
                .style(Style::default().bg(Color::Yellow).fg(Color::Black)),
            Rect::new(x, 1, w, 1));
        let _ = (area, chat_h);
    }

    fn draw_modal(&self, f: &mut Frame, area: Rect, m: &Modal) {
        match m {
            Modal::Help => {
                // F1-F9 are drawn in the bottom button grid; list only the **other** shortcuts here. CJK padded by display width to keep columns aligned.
                let text = vec![
                    Line::from("Shortcuts (F1–F9: see the button grid on the left)"),
                    Line::from(""),
                    Line::from("  List / session tree"),
                    help_pair("↑↓ select", "Enter open / send"),
                    help_pair("Tab switch focus", "PgUp/PgDn page"),
                    help_pair("r rename (server / contact)", "d delete (server / contact)"),
                    help_pair("r group: rename (owner only)", "d group: leave (confirm)"),
                    help_pair("t transfer ownership", "D dissolve group (owner only)"),
                    Line::from(""),
                    Line::from("  Input box"),
                    help_pair("Enter send", "Shift+Enter / Ctrl+J newline"),
                    Line::from("  (Shift+Enter needs kitty protocol; use Ctrl+J on SSH/Windows)"),
                    Line::from(""),
                    Line::from("  Modals"),
                    help_pair("Esc cancel / close", "Enter confirm (y also works)"),
                    help_pair("Approvals: a / Enter approve", "Approvals: d reject"),
                    help_pair("Approvals: y accept transfer", "Approvals: n reject transfer"),
                    help_pair("Members: d remove member", "Forms: Tab / ↑↓ switch fields"),
                    help_pair("Forms: Enter submit", "Servers: a add"),
                    help_pair("Servers: Enter connect", "Servers: c connect all"),
                    Line::from(""),
                    help_pair("Ctrl+Alt+M quit", "keyboard only (no mouse)"),
                    Line::from("  Ctrl+C / Ctrl+Q are ignored; Esc / Enter alone does not quit"),
                    Line::from("  F3 file send is 1v1 only; groups have no file send/download"),
                    Line::from("  received files are saved to <program dir>/received_files/"),
                ];
                self.render_modal(f, area, " Help ", text, modal_width(m));
            }
            Modal::ServerList { sel, form } => {
                let mut lines = vec![
                    Line::from(format!("{} servers", self.core.live_order().len())),
                    Line::from(""),
                ];
                let order = self.core.live_order();
                for (i, sid) in order.iter().enumerate() {
                    // `session()` returns an owned clone; borrow it with `as_ref()` so later uses do not move `s`.
                    let sess = self.core.session(sid);
                    let s = sess.as_ref();
                    let online = s.map(|s| s.status()).unwrap_or(false);
                    let err = s.and_then(|s| s.error());
                    let name = s.map(|s| format!("{}:{}", s.name(), s.port)).unwrap_or_default();
                    let mark = if online { "●" } else if err.is_some() { "✗" } else { "○" };
                    let mut l = format!(" {} {} ({})", mark, name,
                        s.map(|s| s.host.clone()).unwrap_or_default());
                    if i == *sel { l = format!(">{}", &l[1..]); }
                    lines.push(Line::from(l));
                }
                if let Some(f) = form {
                    lines.push(Line::from(""));
                    lines.push(Line::from("Add server (Tab/↑↓ switch, Enter next/save, Esc back)"));
                    let mk = |label: &str, v: &str, on: bool| {
                        Line::from(format!("{} {label}: [{v}]", if on { ">" } else { " " }))
                    };
                    lines.push(mk("Name (optional)", &f.name, f.focus == 0));
                    lines.push(mk("Host", &f.host, f.focus == 1));
                    lines.push(mk("Port", &f.port, f.focus == 2));
                } else {
                    lines.push(Line::from(""));
                    lines.push(Line::from("Enter connect   a add   c connect all   Esc close   Q quit"));
                }
                self.render_modal(f, area, " Servers ", lines, modal_width(m));
            }
            Modal::AddContact { id_field, name_field, focus, msg, .. } => {
                // Show the server name/address, **never the sid** (an unreadable short hash); backend lookups still use the sid.
                let lines = vec![
                    Line::from(format!("Server: {}", self.current_server_label())),
                    Line::from(""),
                    mark_focused(Line::from("Contact ID"), *focus == 0),
                    mark_focused(Line::from(format!("[ {id_field} ]")), *focus == 0),
                    Line::from(""),
                    mark_focused(Line::from("Display name (optional)"), *focus == 1),
                    mark_focused(Line::from(format!("[ {name_field} ]")), *focus == 1),
                    Line::from(""),
                    Line::from(msg.clone()),
                ];
                self.render_modal(f, area, " Add contact ", lines, modal_width(m));
            }
            Modal::CreateGroup { name, nick, msg, .. } => {
                let srv = self.current_server_label();
                let lines = vec![
                    Line::from(format!("Create on server {srv}"))
                        .style(Style::default().fg(Color::Yellow)),
                    Line::from("Group name (encrypted; the server sees no plaintext)"),
                    Line::from(format!("[ {name} ]")),
                    Line::from("My nickname in the group (sent to members via MLS)"),
                    Line::from(format!("[ {nick} ]")),
                    Line::from(""),
                    Line::from(msg.clone()),
                    Line::from(""),
                    Line::from("Tab/↑↓ switch fields   Enter create   Esc cancel"),
                ];
                self.render_modal(f, area, " Create group ", lines, modal_width(m));
            }
            Modal::JoinGroup { gid, text, nick, msg, .. } => {
                let lines = vec![
                    Line::from(format!("Request to join on server {}", self.current_server_label()))
                        .style(Style::default().fg(Color::Yellow)),
                    Line::from("Group ID (10 digits/lowercase letters, provided by the owner)"),
                    Line::from(format!("[ {gid} ]")),
                    Line::from("Request note (encrypted with the owner's public key)"),
                    Line::from(format!("[ {text} ]")),
                    Line::from("My nickname in the group (sent to members via MLS)"),
                    Line::from(format!("[ {nick} ]")),
                    Line::from(""),
                    Line::from(msg.clone()),
                    Line::from(""),
                    Line::from("Tab/↑↓ switch fields   Enter submit request   Esc cancel"),
                ];
                self.render_modal(f, area, " Join group ", lines, modal_width(m));
            }
            Modal::GroupMembers { gid, rows, sel, .. } => {
                let mut lines =
                    vec![Line::from(format!("Members of group {gid} (nicknames come from MLS credentials)"))];
                lines.push(Line::from(""));
                if rows.is_empty() {
                    lines.push(Line::from("(no member information)"));
                }
                for (i, (nick, uid, role)) in rows.iter().enumerate() {
                    let mark = if i == *sel { ">" } else { " " };
                    lines.push(Line::from(format!("{mark} {nick}  <{uid}>  [{role}]")));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("↑↓ select   d remove member (owner only)   Esc close"));
                self.render_modal(f, area, " Members ", lines, modal_width(m));
            }
            Modal::PickSuccessor { gid, rows, sel, for_leave, .. } => {
                let mut lines: Vec<Line> = vec![
                    Line::from(format!("Group ID: {gid}")),
                    Line::from(if *for_leave {
                        "you are the owner; name a new owner before leaving"
                    } else {
                        "transfer ownership (you stay in the group until they confirm)"
                    }),
                    Line::from(""),
                ];
                for (i, (nick, _)) in rows.iter().enumerate() {
                    let style = if i == *sel {
                        Style::default().bg(Color::Yellow).fg(Color::Black)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    lines.push(Line::from(format!("  {nick}")).style(style));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("↑↓ select   Enter confirm transfer and leave   Esc cancel"));
                self.render_modal(f, area, " Pick new owner ", lines, modal_width(m));
            }
            Modal::Notices { rows, sel, expanded, msg } => {
                let flat = notice_flat(rows, expanded);
                let mut lines: Vec<Line> = Vec::new();
                if rows.is_empty() {
                    lines.push(Line::from("(no pending notices)"));
                }
                for (i, (cat, item)) in flat.iter().enumerate() {
                    let mark = if i == *sel { ">" } else { " " };
                    let cnt = rows.iter().filter(|n| n.cat == *cat).count();
                    match item {
                        None => lines.push(
                            Line::from(format!(
                                "{mark} {} {} [{cnt}]",
                                if expanded[*cat] { "v" } else { ">" },
                                NOTICE_CATS[*cat]
                            ))
                            .style(Style::default().fg(if cnt > 0 {
                                Color::Yellow
                            } else {
                                Color::DarkGray
                            })),
                        ),
                        Some(idx) => {
                            // Labels can be long (group name/ID/request text) and must wrap --
                            // otherwise the modal width truncates them and key details (group ID, request note) vanish.
                            for (k, part) in wrap_display(&rows[*idx].label, notice_label_width())
                                .into_iter()
                                .enumerate()
                            {
                                if k == 0 {
                                    lines.push(Line::from(format!("{mark}    {part}")));
                                } else {
                                    lines.push(Line::from(format!("       {part}")));
                                }
                            }
                        }
                    }
                }
                lines.push(Line::from(""));
                lines.push(Line::from(msg.clone()));
                self.render_modal(f, area, " Notices ", lines, modal_width(m));
            }
            Modal::RenameServer { field, .. } => {
                let lines = vec![
                    Line::from("Server display name (local DB only, server unaffected)"),
                    Line::from(""),
                    Line::from(format!("[ {field} ]")),
                    Line::from(""),
                    Line::from("Enter save   Esc cancel"),
                ];
                self.render_modal(f, area, " Rename server ", lines, modal_width(m));
            }
            Modal::RenameGroup { gid, field, msg, .. } => {
                let lines = vec![
                    Line::from(format!("Group ID: {gid}")),
                    Line::from("the name is shared group-wide (the server sees no content)"),
                    Line::from(""),
                    Line::from(format!("[ {field} ]")),
                    Line::from(""),
                    Line::from(msg.clone()),
                ];
                self.render_modal(f, area, " Rename group ", lines, modal_width(m));
            }
            Modal::RenameContact { contact, field, .. } => {
                let lines = vec![
                    Line::from(format!("Contact: {contact}")),
                    Line::from("Display name (local DB only; empty shows the contact ID)"),
                    Line::from(""),
                    Line::from(format!("[ {field} ]")),
                    Line::from(""),
                    Line::from("Enter save   Esc cancel"),
                ];
                self.render_modal(f, area, " Rename contact ", lines, modal_width(m));
            }
            Modal::FilePicker(st) => {
                let mut lines: Vec<Line> = Vec::new();
                lines.push(Line::from(format!("Directory: {}", st.cwd.display()))
                    .style(Style::default().fg(Color::DarkGray)));
                lines.push(Line::from(""));
                let end = (st.scroll + FILE_PICKER_VIS).min(st.entries.len());
                for (i, e) in st.entries[st.scroll..end].iter().enumerate() {
                    let idx = st.scroll + i;
                    let mark = if idx == st.sel { ">" } else { " " };
                    let kind = if e.is_dir { "[dir]" } else { "[file]" };
                    let mut line = format!("{mark} {kind} {}", e.name);
                    if !e.is_dir {
                        line.push_str(&format!("  {}", fmt_size(e.size)));
                    }
                    lines.push(Line::from(line));
                }
                if st.loading {
                    lines.push(Line::from("(reading directory...)")
                        .style(Style::default().fg(Color::DarkGray)));
                } else if st.entries.is_empty() {
                    lines.push(Line::from("(empty directory)").style(Style::default().fg(Color::DarkGray)));
                }
                lines.push(Line::from(""));
                lines.push(Line::from("Enter open/select   Backspace parent directory   Esc cancel")
                    .style(Style::default().fg(Color::DarkGray)));
                self.render_modal(f, area, " Pick a file to send ", lines, modal_width(m));
            }
            Modal::Confirm { title, text, .. } => {
                let lines: Vec<Line> = text.lines().map(|l| Line::from(l.to_string()))
                    .chain(std::iter::once(Line::from("")))
                    .chain(std::iter::once(Line::from("Enter / y confirm, n / Esc cancel")))
                    .collect();
                self.render_modal(f, area, &format!(" {title} "), lines, modal_width(m));
            }
        }
    }

    fn render_modal(&self, f: &mut Frame, area: Rect, title: &str, lines: Vec<Line>, width: u16) {
        let h = (lines.len() as u16) + 2;
        let w = width.min(area.width.saturating_sub(4));
        let x = (area.width.saturating_sub(w)) / 2;
        let y = (area.height.saturating_sub(h)) / 2;
        let rect = Rect::new(x, y, w, h);
        f.render_widget(Clear, rect);
        f.render_widget(
            Block::default().borders(Borders::ALL).title(title)
                .style(Style::default().fg(Color::Yellow)),
            rect);
        f.render_widget(Paragraph::new(lines), Rect::new(x + 2, y + 1, w.saturating_sub(4),
            h.saturating_sub(2)));
    }
}

/// Caret position inside a modal, `(column, row)`.
///
/// Geometry must match `render_modal`: width `min(modal_w, area.width-4)` centered, content at `x+2`,
/// a value row is `"[ " + field + " ]"` so the field's first column is modal x + **4**; columns use
/// **display width** (CJK/full-width = 2, whereas char counts would leave the caret inside a character).
fn modal_caret_pos(
    area: Rect, modal_w: u16, line_count: u16, line_idx: usize, field: &str, max_col: usize,
) -> (u16, u16) {
    let w = modal_w.min(area.width.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(line_count + 2)) / 2;
    let col = disp_width(field).min(max_col);
    (x + 4 + col as u16, y + 1 + line_idx as u16)
}

/// Pick an ID token out of pasted text (10 digits or lowercase letters).
/// Users often copy a whole sentence (e.g. the group-created notice that embeds the group ID) or text with whitespace,
/// which would always fail field validation and look like "paste did nothing"; prefer the whole
/// whitespace-stripped string, else split on non-alphanumeric boundaries and return the first ID-shaped token.
fn extract_id_token(text: &str) -> Option<String> {
    // Length 10: contact IDs are 10 hex chars, group IDs are 10 base36 chars
    const ID_LEN: usize = 10;
    let is_id = |s: &str| {
        s.len() == ID_LEN && s.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
    };

    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if is_id(&compact) {
        return Some(compact);
    }
    text.split(|c: char| !(c.is_ascii_digit() || c.is_ascii_lowercase()))
        .find(|tok| is_id(tok))
        .map(|s| s.to_string())
}

/// **Width** of each modal kind (single source of truth): both `draw_modal` rendering and caret placement use it.
/// F5 once used 62 here and 66 for rendering, a 2-column x offset after centering that showed up as
/// "typed content and caret in different columns" (guarded by `modal_width_matches_render_and_caret`).
fn modal_width(m: &Modal) -> u16 {
    match m {
        Modal::Notices { .. } => 78,
        Modal::Help => 68,
        Modal::ServerList { form: Some(_), .. } => 72,
        Modal::ServerList { .. } => 72,
        Modal::AddContact { .. } => 62,
        Modal::CreateGroup { .. } => 66,
        Modal::JoinGroup { .. } => 70,
        Modal::GroupMembers { .. } => 72,
        Modal::PickSuccessor { .. } => 72,
        Modal::RenameServer { .. } => 60,
        Modal::RenameContact { .. } => 62,
        Modal::RenameGroup { .. } => 66,
        Modal::FilePicker(_) => 72,
        Modal::Confirm { .. } => 64,
    }
}

/// Content line count per modal kind.
/// **Must match the actual `lines` length in `draw_modal`** (vertical centering and the in-modal caret row depend on it).
fn modal_line_count(m: &Option<Modal>) -> u16 {
    match m {
        // Category tree (flattened) + blank + status + hint; one extra line for "(none)" when empty
        Some(Modal::Notices { rows, expanded, .. }) => {
            // Entries wrap, so count wrapped lines; otherwise the modal height and its content disagree
            let flat = notice_flat(rows, expanded);
            let mut n: u16 = 0;
            for (_, item) in &flat {
                match item {
                    None => n += 1,
                    Some(i) => {
                        n += wrap_display(&rows[*i].label, notice_label_width()).len() as u16
                    }
                }
            }
            n + 3 + if rows.is_empty() { 1 } else { 0 }
        }
        // Server / blank / contact ID / [ID] / blank / display name (optional) / [name] / blank / hint
        Some(Modal::AddContact { .. }) => 9,
        // Description / blank / [value] / blank / hint
        Some(Modal::RenameServer { .. }) => 5,
        Some(Modal::CreateGroup { .. }) => 9,
        Some(Modal::JoinGroup { .. }) => 11,
        Some(Modal::GroupMembers { rows, .. }) => (rows.len() as u16) + 5,
        Some(Modal::PickSuccessor { rows, .. }) => (rows.len() as u16) + 5,
        // Contact / display name (optional) / blank / [value] / blank / hint
        Some(Modal::RenameContact { .. }) => 6,
        Some(Modal::RenameGroup { .. }) => 6,
        Some(Modal::Help) => 0, // help self-renders and needs no caret placement
        Some(Modal::ServerList { .. })
        | Some(Modal::FilePicker(_))
        | Some(Modal::Confirm { .. })
        | None => 0,
    }
}

/// Contact order: **online first**, preserving the given order within a group.
/// Uses a stable sort (`sort_by_key`) rather than a comparator, keeping the DB retrieval order (no pinyin re-sorting).
fn order_contacts_online_first<'a>(
    contacts: &'a [store::Contact], online: &HashSet<String>,
) -> Vec<&'a store::Contact> {
    let mut v: Vec<&store::Contact> = contacts.iter().collect();
    v.sort_by_key(|c| !online.contains(&c.username));
    v
}

/// Build the top-left 2x5 button grid (one `Line` per row): F1-F4 left, F5-F9 right.
/// Invariant: every row's **display width must equal `sw`**, or the right border drifts
/// (`button_grid_alignment_and_labels` covers every sidebar width from 24 to 40).
fn build_button_grid(sw: usize, pending_approval: bool) -> Vec<Line<'static>> {
    // One row = 3 + left width + right width, so left + right = sw - 3.
    let cols = sw.saturating_sub(3);
    let lw = cols / 2;
    let rw = cols - lw;
    let lcell = lw.saturating_sub(2);
    let rcell = rw.saturating_sub(2);

    let center = |label: &str, width: usize| -> String {
        let label = fit_button_label(label, width);
        let w = disp_width(&label);
        let pad = width.saturating_sub(w);
        format!("{}{}{}", " ".repeat(pad / 2), label, " ".repeat(pad - pad / 2))
    };

    // Separators must sit in the **same column** as the content rows' middle bar: that bar is at column 2 + lw,
    // so dl = lw; the other segment follows from the total: 3 (frame) + dl + dr = sw.
    let dl = lw;
    let dr = (sw.saturating_sub(3)).saturating_sub(dl);

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(format!("┌{}┬{}┐", "─".repeat(dl), "─".repeat(dr))));
    for (i, row) in BUTTON_ROWS.iter().enumerate() {
        let left = center(row[0], lcell);
        // F7 (group approvals) switches to a clearer label in yellow when work is pending: approvals need a human.
        let is_approval_btn = i == APPROVAL_BUTTON_ROW;
        let right_label = if is_approval_btn && pending_approval {
            APPROVAL_LABEL_ALERT
        } else {
            row[1]
        };
        let right = center(right_label, rcell);
        if is_approval_btn && pending_approval {
            lines.push(Line::from(vec![
                Span::raw(format!("│ {left} │ ")),
                Span::styled(
                    right,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                Span::raw(" │"),
            ]));
        } else {
            lines.push(Line::from(format!("│ {left} │ {right} │")));
        }
        if i + 1 < BUTTON_ROWS.len() {
            lines.push(Line::from(format!("├{}┼{}┤", "─".repeat(dl), "─".repeat(dr))));
        }
    }
    lines.push(Line::from(format!("└{}┴{}┘", "─".repeat(dl), "─".repeat(dr))));

    // Invariant: every row's display width must equal the sidebar width
    debug_assert!(
        lines.iter().all(|l| {
            disp_width(&l.spans.iter().map(|s| s.content.as_ref()).collect::<String>()) == sw
        }),
        "button grid row width does not match the sidebar width {sw}"
    );
    lines
}

/// Fallback for the left button labels: keep the key hint ("F1") as long as possible, then drop it, then truncate.
/// Normal widths (`cell_width >= 10`) always fit; this only matters on very narrow terminals, where overflowing content skews both bordered columns.
fn fit_button_label(label: &str, cell_width: usize) -> String {
    if disp_width(label) <= cell_width {
        return label.to_string();
    }
    let (text, hint) = match label.rsplit_once(' ') {
        Some((t, h)) if h.starts_with('F') => (t, Some(h)),
        _ => (label, None),
    };
    match hint {
        Some(h) => {
            let text_budget = cell_width.saturating_sub(disp_width(h) + 1);
            if text_budget == 0 {
                truncate(h, cell_width) // not even room for the hint: keep the hint only
            } else {
                format!("{} {h}", truncate(text, text_budget))
            }
        }
        None => truncate(label, cell_width),
    }
}

/// Focus style for form fields: bright yellow for the focused one, default for the rest, so the active box is obvious.
fn mark_focused(line: Line<'static>, focused: bool) -> Line<'static> {
    if focused {
        line.style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        line.style(Style::default().fg(Color::DarkGray))
    }
}

/// Local send status -> bubble title suffix; only **genuinely problematic** states get one:
/// - `failed`: WS down or the server rejected it -> `x send failed`
/// - `unknown`: leftover from a previous run, receipt lost -> `- unconfirmed`
/// `delivered`/`queued`/`sent` all mean the server accepted it and get **no marker** (calling them "undelivered" would be a false alarm).
fn local_status_suffix(status: Option<&str>) -> Option<(&'static str, Color)> {
    match status {
        Some(store::LOCAL_STATUS_FAILED) => Some(("  ✗ send failed", Color::Red)),
        Some(store::LOCAL_STATUS_UNKNOWN) => Some(("  · unconfirmed", Color::DarkGray)),
        _ => None,
    }
}

/// Whether a key event should quit (`Ctrl+Alt+M`). All three terminal encodings must be accepted:
///   1) kitty / CSI-u keyboard protocol: reports `Char('m') + CONTROL|ALT` faithfully;
///   2) legacy terminals (tmux, xterm, ...): encode Ctrl+Alt+M as `ESC(0x1b) + CR(0x0d)`, which crossterm
///      parses as `Enter + ALT` -- **the most common path** (this project's `--keytest` recorded exactly that);
///   3) `ESC` and `CR` arriving separately (tmux delays a lone ESC): recognized via the `last_esc` 100ms window;
///   4) terminals treating Alt as Meta (Xshell, macOS Option, SecureCRT) encode `ESC + 'm'` -> `Alt+m`.
/// Known cost: case 2 is byte-identical to a real Alt+Enter and cannot be distinguished, so Alt+Enter
/// cannot insert a newline; use `Ctrl+J` (universal) or `Shift+Enter` (needs the kitty protocol).
fn is_exit_key(k: &KeyEvent, last_esc: Option<Instant>) -> bool {
    let ctrl_alt_m = k.modifiers.contains(KeyModifiers::CONTROL)
        && k.modifiers.contains(KeyModifiers::ALT)
        && matches!(k.code, KeyCode::Char('m') | KeyCode::Char('M'));
    // 4) Terminals treating Alt as Meta (Xshell / macOS Option / SecureCRT) encode Ctrl+Alt+M
    //    as `ESC + 'm'` -> crossterm reports **Alt+m (no CONTROL)**, different bytes from case 2.
    let alt_m = k.modifiers.contains(KeyModifiers::ALT)
        && !k.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(k.code, KeyCode::Char('m') | KeyCode::Char('M'));
    let esc_cr = matches!(k.code, KeyCode::Enter)
        && k.modifiers.contains(KeyModifiers::ALT);
    let split_esc_cr = matches!(k.code, KeyCode::Enter)
        && last_esc
            .map(|t| t.elapsed() <= Duration::from_millis(100))
            .unwrap_or(false);
    ctrl_alt_m || alt_m || esc_cr || split_esc_cr
}

/// Per line (start char index, char length), at least one line (supports the empty line after a trailing newline)
fn line_meta(input: &str) -> Vec<(usize, usize)> {
    let mut v = vec![(0usize, 0usize)];
    for ch in input.chars() {
        let i = v.len() - 1;
        if ch == '\n' {
            let start = v[i].0 + v[i].1 + 1;
            v.push((start, 0));
        } else {
            v[i].1 += 1;
        }
    }
    v
}

/// Caret char index -> (line, char offset within the line)
fn cursor_line_col(input: &str, cursor: usize) -> (usize, usize) {
    let mut line = 0usize;
    let mut col = 0usize;
    for (i, ch) in input.chars().enumerate() {
        if i >= cursor { break; }
        if ch == '\n' { line += 1; col = 0; } else { col += 1; }
    }
    (line, col)
}

/// Human-readable file size
fn fmt_size(n: u64) -> String {
    let mut v = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if v < 1024.0 || unit == "GB" {
            return if unit == "B" { format!("{n} B") } else { format!("{v:.1} {unit}") };
        }
        v /= 1024.0;
    }
    format!("{n} B")
}

fn truncate(s: &str, w: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for ch in s.chars() {
        let cw = char_width(ch);
        if used + cw > w { break; }
        out.push(ch);
        used += cw;
    }
    out
}

fn char_width(c: char) -> usize {
    match c as u32 {
        0x1100..=0x115F | 0x2E80..=0xA4CF | 0xAC00..=0xD7A3 | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F | 0xFF00..=0xFF60 | 0xFFE0..=0xFFE6 | 0x1F300..=0x1FAFF => 2,
        _ => 1,
    }
}

fn disp_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

/// Two-column help layout: two shortcuts per line.
/// Padding must use **display width** -- `{:<n}` pads by char count and CJK (2 columns) skews the columns.
fn help_pair(left: &str, right: &str) -> Line<'static> {
    const COL: usize = 31;
    let pad = COL.saturating_sub(disp_width(left));
    Line::from(format!("  {}{}{}", left, " ".repeat(pad), right))
}

/// Wrap by display width (CJK counts as 2 columns)
fn wrap_display(s: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for para in s.split('\n') {
        if para.is_empty() { out.push(String::new()); continue; }
        let mut cur = String::new();
        let mut used = 0;
        for ch in para.chars() {
            let cw = char_width(ch);
            if used + cw > width && !cur.is_empty() {
                out.push(cur.clone());
                cur.clear();
                used = 0;
            }
            cur.push(ch);
            used += cw;
        }
        out.push(cur);
    }
    if out.is_empty() { out.push(String::new()); }
    out
}


/// Caret position on the master-key screen (column, row).
/// Layout (`prompt_master_key`'s `lines`, rendering starts at y+1): y+1 note / y+3 master-key label /
/// y+4 [value] / y+5 confirm-master-key label / y+6 [value]. A value row is `"[ " + value + " ]"` rendered from `x+2`,
/// so values start at `x+4`: caret column = `x + 4 + chars typed`, shared by both boxes.
/// **The note must stay one line**: if it wraps, every row below shifts while this function returns absolute coordinates and the caret leaves the box.
fn master_key_caret(
    x: u16, y: u16, which: usize, field: &str, field2: &str,
) -> (u16, u16) {
    let (value, row_offset) = if which == 0 {
        (field, 3u16)
    } else {
        (field2, 5u16)
    };
    (x + 4 + value.chars().count() as u16, y + 1 + row_offset)
}

/// Master-key (unlock/setup) screen: returns the entered passphrase; Esc returns None
pub fn prompt_master_key(
    terminal: &mut ratatui::DefaultTerminal,
    title: &str,
    note: &str,
    confirm: bool,
    error: Option<&str>,
) -> Result<Option<String>> {
    let mut field = String::new();
    let mut field2 = String::new();
    let mut which = 0usize;
    let mut err = error.map(|s| s.to_string()).unwrap_or_default();
    loop {
        terminal.draw(|f| {
            let area = f.area();
            // The two input boxes must have **structurally identical** layouts (label on one row, value on the next),
            // else the caret column needs per-label compensation -- the first version put confirm-master-key label and its box on one row and the caret shifted left.
            let mut lines = vec![
                Line::from(note.to_string()).style(Style::default().fg(Color::DarkGray)),
                Line::from(""),
                Line::from("Master key:"),
                Line::from(format!("[ {} ]", "*".repeat(field.chars().count()))),
            ];
            if confirm {
                lines.push(Line::from("Confirm master key:"));
                lines.push(Line::from(format!("[ {} ]", "*".repeat(field2.chars().count()))));
            } else {
                lines.push(Line::from(""));
                lines.push(Line::from(""));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(err.clone()).style(Style::default().fg(Color::Red)));
            lines.push(Line::from("Enter confirm   Esc cancel").style(Style::default().fg(Color::DarkGray)));
            let h = lines.len() as u16 + 2;
            let w = 62.min(area.width.saturating_sub(4));
            let x = (area.width.saturating_sub(w)) / 2;
            let y = (area.height.saturating_sub(h)) / 2;
            f.render_widget(Clear, Rect::new(x, y, w, h));
            f.render_widget(Block::default().borders(Borders::ALL).title(title)
                .style(Style::default().fg(Color::Yellow)), Rect::new(x, y, w, h));
            f.render_widget(Paragraph::new(lines), Rect::new(x + 2, y + 1, w - 4, h - 2));
            let (cx, cy) = master_key_caret(x, y, which, &field, &field2);
            f.set_cursor_position((cx, cy));
        })?;
        // Master-key input happens before `Ui::run`, so the watchdog thread is not running yet; a terminal
        // vanishing here would still busy-spin inside crossterm (see terminal_hung_up), so check and exit explicitly.
        if terminal_hung_up() {
            anyhow::bail!("terminal closed; master key input cancelled");
        }
        if event::poll(Duration::from_millis(100))? {
            match event::read() {
                Ok(CtEvent::Key(k)) => {
                match k.code {
                    KeyCode::Esc => return Ok(None),
                    KeyCode::Tab if confirm => which = 1 - which,
                    KeyCode::Backspace => {
                        if which == 0 { field.pop(); } else { field2.pop(); }
                    }
                    KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                        if which == 0 { field.push(c); } else { field2.push(c); }
                    }
                    KeyCode::Enter => {
                        if confirm {
                            if which == 0 { which = 1; continue; }
                            if field != field2 {
                                err = "the two entries do not match; try again".into();
                                field.clear(); field2.clear(); which = 0; continue;
                            }
                            if field.chars().count() < 6 {
                                err = "must be at least 6 characters long".into(); continue;
                            }
                        } else if field.is_empty() {
                            err = "cannot be empty".into(); continue;
                        }
                        return Ok(Some(field));
                    }
                    _ => {}
                }
                }
                Ok(_) => {}
                // If the terminal is gone, read returns EOF/an error: that is not a keypress
                Err(_) => anyhow::bail!("failed to read a terminal event (the terminal may be closed)"),
            }
        }
    }
}

#[cfg(test)]
mod ui_tests {
    use super::is_exit_key;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::time::{Duration, Instant};

    fn key(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    /// Regression: legacy terminals encode Ctrl+Alt+M as ESC+CR (crossterm: Enter+ALT); an earlier version accepted only Char('m') and those terminals could not quit.
    #[test]
    fn legacy_enter_alt_is_exit() {
        assert!(is_exit_key(
            &key(KeyCode::Enter, KeyModifiers::ALT), None));
    }

    #[test]
    fn kitty_ctrl_alt_m_is_exit() {
        let mods = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert!(is_exit_key(&key(KeyCode::Char('m'), mods), None));
        assert!(is_exit_key(&key(KeyCode::Char('M'), mods), None));
    }

    /// Regression: terminals treating Alt as Meta (Xshell / macOS Option / SecureCRT) encode Ctrl+Alt+M
    /// as `ESC + 'm'`, which crossterm reports as **Alt+m (no CONTROL)**. A version accepting only three
    /// encodings left those terminals **completely unable to quit** (short of killing the process elsewhere).
    #[test]
    fn alt_m_from_meta_terminals_is_exit() {
        assert!(is_exit_key(&key(KeyCode::Char('m'), KeyModifiers::ALT), None));
        assert!(is_exit_key(&key(KeyCode::Char('M'), KeyModifiers::ALT), None));
    }

    #[test]
    fn split_esc_then_enter_within_window_is_exit() {
        assert!(is_exit_key(
            &key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Instant::now())));
    }

    #[test]
    fn split_esc_then_enter_after_window_is_not_exit() {
        let stale = Instant::now() - Duration::from_millis(150);
        assert!(!is_exit_key(&key(KeyCode::Enter, KeyModifiers::NONE), Some(stale)));
    }

    /// Regression: `delivered=false` means only that the peer is offline and the message is queued, i.e. **success**; the bubble must never be marked "undelivered".
    #[test]
    fn queued_and_delivered_are_not_marked_as_problem() {
        use crate::store::{
            LOCAL_STATUS_DELIVERED, LOCAL_STATUS_FAILED, LOCAL_STATUS_QUEUED,
            LOCAL_STATUS_SENT, LOCAL_STATUS_UNKNOWN,
        };
        for ok in [LOCAL_STATUS_DELIVERED, LOCAL_STATUS_QUEUED, LOCAL_STATUS_SENT, ""] {
            assert!(super::local_status_suffix(Some(ok)).is_none(),
                "status {ok:?} is delivered/queued and must get no suffix");
        }
        assert_eq!(super::local_status_suffix(Some(LOCAL_STATUS_FAILED)).map(|x| x.0),
                   Some("  ✗ send failed"));
        assert_eq!(super::local_status_suffix(Some(LOCAL_STATUS_UNKNOWN)).map(|x| x.0),
                   Some("  · unconfirmed"));
        // Old DB rows lack this field
        assert!(super::local_status_suffix(None).is_none());
    }

    /// **Regression**: users paste whole chat lines, so an ID must be extractable (otherwise paste looks broken).
    #[test]
    fn extract_id_token_from_pasted_sentences() {
        use super::extract_id_token;

        assert_eq!(extract_id_token("  abc1234567  ").as_deref(), Some("abc1234567"));
        assert_eq!(extract_id_token("abc1234567").as_deref(), Some("abc1234567"));
        assert_eq!(extract_id_token("abc\n1234567").as_deref(), Some("abc1234567"));

        assert_eq!(
            extract_id_token("group created dz0s3e2rke (send the group ID to others so they can join)").as_deref(),
            Some("dz0s3e2rke")
        );
        assert_eq!(
            extract_id_token("group_id = 5c02abdac4").as_deref(),
            Some("5c02abdac4"),
            "a prefixed form must also be picked out"
        );

        assert_eq!(extract_id_token("a sentence with no ID"), None);
        assert_eq!(extract_id_token("abc"), None);          // too short
        assert_eq!(extract_id_token("ABC1234567"), None);   // uppercase does not count (IDs are lowercase only)
    }

    /// **Regression**: modal width must have a single source -- F5 once rendered at 66 and placed the caret at 62,
    /// a 2-column x offset after centering that showed up as "typed content and caret in different columns".
    #[test]
    fn modal_width_matches_render_and_caret() {
        use super::{modal_caret_pos, modal_width, Modal};
        use ratatui::layout::Rect;

        let area = Rect::new(0, 0, 120, 40);

        let cases: Vec<(Modal, &str)> = vec![
            (Modal::Help, ""),
            (Modal::RenameServer { sid: "s".into(), field: String::new() }, ""),
            (Modal::RenameContact {
                sid: "s".into(), contact: "c".into(), field: String::new(),
            }, ""),
            (Modal::CreateGroup {
                name: String::new(), nick: String::new(), focus: 0,
                msg: String::new(), busy: false,
            }, ""),
            (Modal::JoinGroup {
                gid: String::new(), text: String::new(), nick: String::new(),
                focus: 0, msg: String::new(), busy: false,
            }, ""),
            (Modal::GroupMembers { sid: "s".into(), gid: "g".into(), rows: vec![], sel: 0 }, ""),
        ];

        for (m, field) in &cases {
            let w = modal_width(m);
            assert!(w >= 40 && w <= 90, "unexpected modal width: {w}");

            // Same geometry as render_modal: content at x+2, a value row is "[ " + value, so the first value column is x+4
            let w_eff = w.min(area.width.saturating_sub(4));
            let x = area.x + (area.width.saturating_sub(w_eff)) / 2;
            let (cx, _) = modal_caret_pos(area, w, 8, 1, field, 60);
            assert_eq!(cx, x + 4, "with an empty field the caret must be in the first value column (width {w})");

            let (cx2, _) = modal_caret_pos(area, w, 8, 1, "ＡＢab", 60);
            assert_eq!(cx2, x + 4 + 2 * 2 + 2, "full-width chars count as 2 columns; the caret must shift right by 6");
        }
    }

    /// Modal caret rows must be self-consistent with `modal_line_count`, or the caret lands outside the modal.
    #[test]
    fn modal_caret_layout_is_self_consistent() {
        use super::modal_line_count;
        use crate::ui::Modal;

        let cases: Vec<(Modal, usize, u16)> = vec![
            (Modal::AddContact {
                id_field: String::new(), name_field: String::new(), focus: 0,
                msg: String::new(), req: None, sent: false,
            }, 3, 9),
            (Modal::AddContact {
                id_field: String::new(), name_field: String::new(), focus: 1,
                msg: String::new(), req: None, sent: false,
            }, 6, 9),
            (Modal::RenameServer { sid: "s".into(), field: String::new() }, 2, 5),
            (Modal::RenameContact {
                sid: "s".into(), contact: "c".into(), field: String::new(),
            }, 3, 6),
        ];
        for (modal, caret_line, expect_lines) in cases {
            let m = Some(modal);
            assert_eq!(modal_line_count(&m), expect_lines,
                "modal_line_count and draw_modal disagree on the line count");
            assert!(caret_line < expect_lines as usize,
                "caret line {caret_line} is beyond the content area {expect_lines} lines");
        }
    }

    /// Regression: typing CJK while renaming a server must leave the caret **after the last character** (counting chars instead of display width once shifted it left).
    #[test]
    fn modal_caret_column_after_cjk_text() {
        use super::{disp_width, modal_caret_pos};
        use ratatui::layout::Rect;

        let area = Rect::new(0, 0, 100, 30);
        let w = 60u16;

        let (col_zh, _) = modal_caret_pos(area, w, 5, 2, "ＡＢＣ1", 40);
        let x = (100 - w) / 2;
        assert_eq!(col_zh, x + 4 + disp_width("ＡＢＣ1") as u16,
            "the full-width caret column must use display width (4+... columns)");
        assert_eq!(disp_width("ＡＢＣ1"), 7, "3 full-width chars (2 columns each) + '1' (1 column) = 7 columns");

        let (col_ascii, _) = modal_caret_pos(area, w, 5, 2, "srv-1", 40);
        assert_eq!(col_ascii, x + 4 + 5);

        let (col_mix, _) = modal_caret_pos(area, w, 5, 2, "ＡaＢ", 40);
        assert_eq!(col_mix, x + 4 + disp_width("ＡaＢ") as u16);

        let (col_long, _) = modal_caret_pos(area, w, 5, 2, &"Ａ".repeat(50), 40);
        assert_eq!(col_long, x + 4 + 40);
    }

    /// With pending notices: the F7 label becomes the yellow "has notices" variant in yellow; otherwise unchanged.
    #[test]
    fn approval_button_reflects_pending_state() {
        use super::{build_button_grid, disp_width};
        let text_of =
            |l: &ratatui::text::Line<'static>| -> String {
                l.spans.iter().map(|s| s.content.as_ref()).collect()
            };

        let normal: String = build_button_grid(28, false)
            .iter().map(text_of).collect::<Vec<_>>().join("\n");
        assert!(normal.contains("Messages F7"), "normal state must show the Messages F7 label");
        assert!(!normal.contains("Alerts F7"), "the normal state must not show the alert label");

        let alert_lines = build_button_grid(28, true);
        let alert: String = alert_lines.iter().map(text_of).collect::<Vec<_>>().join("\n");
        assert!(alert.contains("Alerts F7"), "pending notices must show the Alerts F7 label");
        assert!(!alert.contains("Messages F7"), "the alert state must not show the normal label");

        // It must actually be yellow (not just a different label)
        let yellow = alert_lines.iter().any(|l| {
            l.spans.iter().any(|sp| {
                sp.content.contains("Alerts")
                    && sp.style.fg == Some(ratatui::style::Color::Yellow)
            })
        });
        assert!(yellow, "the Alerts F7 label must be yellow");

        // Both states must have equal width (or the two bordered columns skew)
        for sw in [24usize, 26, 28, 30, 34] {
            let a = build_button_grid(sw, true);
            let b = build_button_grid(sw, false);
            assert_eq!(a.len(), b.len(), "sw={sw}: line counts must match");
            for (x, y) in a.iter().zip(b.iter()) {
                assert_eq!(
                    disp_width(&text_of(x)),
                    disp_width(&text_of(y)),
                    "sw={sw}: both states must have equal row widths"
                );
            }
        }
    }

    /// Two-column button grid: every row's display width must equal the sidebar width (or the right border drifts), and all 8 function-key hints must appear.
    #[test]
    fn button_grid_alignment_and_labels() {
        use super::{build_button_grid, disp_width};

        for sw in 24usize..=40 {
            let lines = build_button_grid(sw, false);
            // 5 button rows + 6 border rows = 11 lines
            assert_eq!(lines.len(), 11, "sw={sw}: wrong line count");
            for (i, line) in lines.iter().enumerate() {
                let text: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                assert_eq!(disp_width(&text), sw,
                    "sw={sw}: row {i} has the wrong width: {text:?}");
            }
            let joined: String = lines.iter()
                .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
                .collect::<Vec<_>>().join("\n");
            for hint in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"] {
                assert!(joined.contains(hint), "sw={sw} is missing {hint}: \n{joined}");
            }
        }
    }

    /// Regression: the frame's ">"/"+"/"v" must be in the **same column** as the content rows' middle "|" (a `dl = lw - 1` once shifted everything left by one).
    #[test]
    fn button_grid_dividers_share_one_column() {
        use super::{build_button_grid, disp_width};
        let text_of = |l: &ratatui::text::Line<'static>| -> String {
            l.spans.iter().map(|s| s.content.as_ref()).collect()
        };
        let col_of = |t: &str, needle: char, nth: usize| -> Option<usize> {
            let mut seen = 0usize;
            let mut col = 1usize;
            for ch in t.chars() {
                if ch == needle {
                    seen += 1;
                    if seen == nth { return Some(col); }
                }
                col += disp_width(&ch.to_string());
            }
            None
        };

        for sw in 24usize..=44 {
            let g = build_button_grid(sw, false);
            let rows: Vec<String> = g.iter().map(text_of).collect();

            // Column of the 2nd "|" in the content row (index 1), i.e. the split position
            let want = col_of(&rows[1], '│', 2).expect("the content row must have a 2nd vertical bar");
            // Every frame row (top/middle/bottom) must place its ">"/"+"/"v" in that same column
            for (i, sep) in [(0usize, '┬'), (2, '┼'), (4, '┼'), (6, '┼'), (8, '┼'), (10, '┴')] {
                let got = col_of(&rows[i], sep, 1)
                    .unwrap_or_else(|| panic!("sw={sw}: row {i} is missing {sep}"));
                assert_eq!(got, want,
                    "sw={sw}: row {i} separator {sep} is at column {got}, the content-row bar at column {want}");
            }
            for (i, t) in rows.iter().enumerate() {
                assert_eq!(disp_width(t), sw, "sw={sw}: row {i} has the wrong width");
            }
        }
    }

    /// Very narrow cell: drop the label first, keep the key hint, and never overflow.
    #[test]
    fn button_label_fits_narrow_cells() {
        use super::{disp_width, fit_button_label};
        for w in 1usize..=12 {
            for label in ["Servers F1", "NewGroup F5", "Messages F7", "Spare F8"] {
                let out = fit_button_label(label, w);
                assert!(disp_width(&out) <= w,
                    "w={w} label={label:?} result {out:?} overflows the cell");
            }
        }
        assert_eq!(fit_button_label("Servers F1", 10), "Servers F1");
        assert_eq!(fit_button_label("Servers F1", 2), "F1");
    }

    /// The sidebar width floor must fit the whole two-column button grid (its longest right-column label untruncated); lowering it would silently distort labels.
    #[test]
    fn button_grid_needs_at_least_28_columns() {
        use super::{build_button_grid, disp_width};
        let text_of = |l: &ratatui::text::Line<'static>| -> String {
            l.spans.iter().map(|s| s.content.as_ref()).collect()
        };

        let joined: String = build_button_grid(28, false).iter().map(text_of).collect::<Vec<_>>().join("\n");
        assert!(joined.contains("NewGroup F5"), "at 28 columns the right-column labels must be fully visible:\n{joined}");
        assert!(joined.contains("Messages F7"), "at 28 columns the right-column labels must be fully visible:\n{joined}");

        let joined27: String = build_button_grid(27, false).iter().map(text_of).collect::<Vec<_>>().join("\n");
        assert!(!joined27.contains("NewGroup F5"),
            "at 27 columns it must no longer fit (if it does, the floor could be lower and the test needs updating):\n{joined27}");

        for sw in 28usize..=40 {
            let g = build_button_grid(sw, false);
            assert_eq!(g.len(), 11, "sw={sw}: the grid must have 11 rows");
            for (i, l) in g.iter().enumerate() {
                assert_eq!(disp_width(&text_of(l)), sw, "sw={sw}: row {i} has the wrong width");
            }
        }
    }

    /// Online contacts sort first, offline after; order within a group is preserved (no pinyin re-sorting).
    #[test]
    fn contacts_online_first_and_stable() {
        use super::order_contacts_online_first;
        use std::collections::HashSet;

        let mk = |name: &str| crate::store::Contact {
            server_id: "s".into(), username: name.into(), nickname: None,
            public_key: Some("PEM".into()), deleted: 0,
        };
        // DB order: a b c d (none has a nickname)
        let rows = vec![mk("a"), mk("b"), mk("c"), mk("d")];

        let online: HashSet<String> = ["b", "d"].iter().map(|s| s.to_string()).collect();
        let got: Vec<String> = order_contacts_online_first(&rows, &online)
            .iter().map(|c| c.username.clone()).collect();
        assert_eq!(got, vec!["b", "d", "a", "c"]);

        let none = HashSet::new();
        let got: Vec<String> = order_contacts_online_first(&rows, &none)
            .iter().map(|c| c.username.clone()).collect();
        assert_eq!(got, vec!["a", "b", "c", "d"]);

        let all: HashSet<String> = rows.iter().map(|c| c.username.clone()).collect();
        let got: Vec<String> = order_contacts_online_first(&rows, &all)
            .iter().map(|c| c.username.clone()).collect();
        assert_eq!(got, vec!["a", "b", "c", "d"]);

        assert!(order_contacts_online_first(&[], &online).is_empty());

        let extra: HashSet<String> = ["b", "zzz"].iter().map(|s| s.to_string()).collect();
        let got: Vec<String> = order_contacts_online_first(&rows, &extra)
            .iter().map(|c| c.username.clone()).collect();
        assert_eq!(got, vec!["b", "a", "c", "d"]);
    }

    /// Regression: the caret in the master-key screen's 2nd input box must stay inside the box -- the original put label and box on one row
    /// but computed the column with the "label on its own row" x+4, shifting it left by a label width.
    #[test]
    fn master_key_caret_is_inside_both_fields() {
        use super::master_key_caret;
        let (x, y) = (14u16, 7u16);

        assert_eq!(master_key_caret(x, y, 0, "", ""), (x + 4, y + 4));
        assert_eq!(master_key_caret(x, y, 0, "123456", ""), (x + 10, y + 4));

        assert_eq!(master_key_caret(x, y, 1, "", ""), (x + 4, y + 6));
        assert_eq!(master_key_caret(x, y, 1, "", "123456"), (x + 10, y + 6));

        // Both boxes must use the same column formula: equal input length -> equal column
        let a = master_key_caret(x, y, 0, "abcdef", "zzz");
        let b = master_key_caret(x, y, 1, "zzz", "abcdef");
        assert_eq!(a.0, b.0, "both input boxes must use the same caret column formula");
        assert_ne!(a.1, b.1, "the two input boxes must be on different rows");
    }

    /// Reproduce the master-key modal layout with a real TestBackend: the caret must be on the row holding `[ ]` and between the brackets.
    /// This compares the real render buffer rather than hand-computed row numbers -- two earlier fixes failed because hand math disagreed with ratatui.
    #[test]
    fn master_key_cursor_lands_on_input_line() {
        use ratatui::backend::TestBackend;
        use ratatui::layout::Rect;
        use ratatui::style::{Color, Style};
        use ratatui::text::Line;
        use ratatui::widgets::{Block, Borders, Clear, Paragraph};
        use ratatui::Terminal;

        let labels = ["Master key:", "Confirm master key:"];
        for which in [0usize, 1] {
            for value in ["", "123456"] {
                let backend = TestBackend::new(90, 24);
                let mut term = Terminal::new(backend).unwrap();
                let (field, field2) = if which == 0 {
                    (value.to_string(), String::new())
                } else {
                    (String::new(), value.to_string())
                };
                let mut caret = (0u16, 0u16);
                term.draw(|f| {
                    let area = f.area();
                    let note = "First run: set the DB master key (\u{2265}6 chars, RAM only)";
                    // Layout identical to prompt_master_key (labels defined outside the loop and shared across closures)
                    let mut lines = vec![
                        Line::from(note.to_string()).style(Style::default().fg(Color::DarkGray)),
                        Line::from(""),
                    ];
                    for (i, lab) in labels.iter().enumerate() {
                        lines.push(Line::from(*lab));
                        let v = if i == 0 { &field } else { &field2 };
                        lines.push(Line::from(format!("[ {} ]", "*".repeat(v.chars().count()))));
                    }
                    lines.push(Line::from(""));
                    lines.push(Line::from(""));
                    lines.push(Line::from("Enter confirm   Esc cancel").style(Style::default().fg(Color::DarkGray)));
                    let h = lines.len() as u16 + 2;
                    let w = 62.min(area.width.saturating_sub(4));
                    let x = (area.width.saturating_sub(w)) / 2;
                    let y = (area.height.saturating_sub(h)) / 2;
                    f.render_widget(Clear, Rect::new(x, y, w, h));
                    f.render_widget(Block::default().borders(Borders::ALL)
                        .style(Style::default().fg(Color::Yellow)), Rect::new(x, y, w, h));
                    f.render_widget(Paragraph::new(lines), Rect::new(x + 2, y + 1, w - 4, h - 2));
                    caret = super::master_key_caret(x, y, which, &field, &field2);
                    f.set_cursor_position(caret);
                }).unwrap();

                let buf = term.backend().buffer().clone();
                let row: String = (0..90).map(|c| buf[(c, caret.1)].symbol().to_string()).collect();
                let col = caret.0 as usize;
                // Must use **char indices**: `row.find()` returns a byte offset and rows contain multi-byte frame characters like `|`, which would misplace the caret.
                let open = row.chars().position(|c| c == '[').unwrap_or_else(|| panic!(
                    "which={which}: caret row is not an input row (no '['): {row:?}"));
                let close = row.chars().position(|c| c == ']').expect("this row must have ]");
                assert!(col > open && col <= close,
                    "which={which} value={value:?}: caret column {col} is outside ({open},{close}]; row={row:?}");
                // Layout contract: the caret must be on a line containing `[`, and that line must be the which-th such line.
                let box_rows: Vec<u16> = (0..24u16).filter(|r| {
                    let l: String = (0..90)
                        .map(|c| buf[(c, *r)].symbol().to_string()).collect();
                    l.contains('[')
                }).collect();
                assert!(box_rows.contains(&caret.1),
                    "which={which}: caret row {} is not an input row; rows containing [={box_rows:?}",
                    caret.1);
                assert_eq!(box_rows.iter().position(|r| *r == caret.1), Some(which),
                    "which={which}: caret landed on input row {:?}; box_rows={box_rows:?}",
                    box_rows.iter().position(|r| *r == caret.1));
                let _ = labels;
            }
        }
    }

    #[test]
    fn plain_keys_are_not_exit() {
        // Enter / Esc / Ctrl+M / capital M alone must not quit
        // (`Alt+m` is excluded here: it is Ctrl+Alt+M on Xshell-like terminals, see the test above)
        for (code, mods) in [
            (KeyCode::Enter, KeyModifiers::NONE),
            (KeyCode::Esc, KeyModifiers::NONE),
            (KeyCode::Char('m'), KeyModifiers::CONTROL),
            (KeyCode::Char('M'), KeyModifiers::NONE),
            (KeyCode::Char('m'), KeyModifiers::NONE),
        ] {
            assert!(!is_exit_key(&key(code, mods), None), "{code:?} {mods:?} must not quit");
        }
    }
}

#[cfg(test)]
mod multiline_tests {
    use super::{cursor_line_col, line_meta};

    #[test]
    fn test_line_meta() {
        assert_eq!(line_meta(""), vec![(0, 0)]);
        assert_eq!(line_meta("abc"), vec![(0, 3)]);
        assert_eq!(line_meta("ab\ncd"), vec![(0, 2), (3, 2)]);
        // A trailing newline produces one more empty line
        assert_eq!(line_meta("ab\ncde\n"), vec![(0, 2), (3, 3), (7, 0)]);
    }

    #[test]
    fn test_disp_width_cjk() {
        assert_eq!(super::disp_width("abc"), 3);
        assert_eq!(super::disp_width("ＡＢ"), 4);
        assert_eq!(super::disp_width("aＡb"), 4);
        assert_eq!(super::disp_width("ＡＢabc"), 7);
    }

    #[test]
    fn test_cursor_line_col() {
        let s = "ab\ncde\n";
        assert_eq!(cursor_line_col(s, 0), (0, 0));
        assert_eq!(cursor_line_col(s, 2), (0, 2));
        assert_eq!(cursor_line_col(s, 3), (1, 0));
        assert_eq!(cursor_line_col(s, 6), (1, 3));
        assert_eq!(cursor_line_col(s, 7), (2, 0));
        assert_eq!(cursor_line_col(s, 99), (2, 0));
    }
}

