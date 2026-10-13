//! Runtime diagnostic log, written to `<executable dir>/tui_stderr.log` instead of stderr: once
//! ratatui owns the terminal, `eprintln!` output would be painted into the chat area and never cleared.
//! Usage: `crate::tui_log!("...")`; before `init` (e.g. in tests) lines are silently dropped to keep test output clean.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

static SINK: OnceLock<Mutex<Option<std::fs::File>>> = OnceLock::new();

/// Log file path: `tui_stderr.log` next to the executable (as the build script expects).
pub fn log_file_path() -> PathBuf {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    dir.join("tui_stderr.log")
}

/// Open (or create) the log file and start accepting lines; repeat calls are no-ops.
pub fn init() -> std::io::Result<PathBuf> {
    let path = log_file_path();
    let f = OpenOptions::new().create(true).append(true).open(&path)?;
    // Separator for this startup, so separate runs stay distinguishable
    {
        let mut f = f;
        let _ = writeln!(f, "──── {} ────", timestamp());
        let _ = SINK.set(Mutex::new(Some(f)));
        return Ok(path);
    }
}

/// Write one timestamped log line; arguments work as in `format!`.
pub fn write_line(args: std::fmt::Arguments<'_>) {
    let Some(sink) = SINK.get() else { return }; // not initialized: drop
    let Ok(mut guard) = sink.lock() else { return };
    let Some(f) = guard.as_mut() else { return };
    let _ = writeln!(f, "[{}] {}", timestamp(), args);
}

fn timestamp() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Write a runtime log line (effective only after `log::init()`); named `tui_log!` to avoid
/// confusion with the `log` module.
#[macro_export]
macro_rules! tui_log {
    ($($arg:tt)*) => {
        $crate::log::write_line(format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::{write_line, Mutex, SINK};

    /// Regression: runtime logs must land in a **file**, never stderr — ratatui owns the screen
    /// and stderr would pollute the chat area (this once printed the stale-message notice there).
    #[test]
    fn writes_to_file_not_stderr() {
        let path = std::env::temp_dir()
            .join(format!("mcrt_log_test_{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let f = std::fs::OpenOptions::new()
                .create(true).append(true).open(&path).unwrap();
            let _ = SINK.set(Mutex::new(Some(f)));
        }
        crate::tui_log!("regression marker {}", 42);
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("regression marker 42"), "log was not written to file: {body:?}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_before_init_is_silently_dropped() {
        // Must not panic before init: other modules may log at any time
        write_line(format_args!("ignored"));
    }
}
