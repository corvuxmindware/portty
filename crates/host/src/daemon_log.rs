//! The background host's log file.
//!
//! A detached daemon has no terminal to log to: once the "phone connected" banner
//! is printed its stdout and stderr go to /dev/null, and on Windows it starts with
//! no console at all. Every warning it logged used to vanish - which is how a
//! phone stuck on "wrong PIN" left nothing on the laptop to diagnose it with. In
//! background mode the same log lines are therefore also written to
//! [`LOG_FILE`] in the data directory.
//!
//! - **Owner-only:** 0600 (Windows: an owner-only DACL) inside the owner-only
//!   data directory, since it names paired devices and network addresses.
//! - **Bounded:** at [`MAX_LOG_BYTES`] the file moves to `portty-host.log.1`,
//!   replacing the older one, and a fresh file starts - so the pair never holds
//!   much more than twice that.
//! - **No secrets:** tracing events never carry tickets, PINs, phrases or tokens.
//!   The pairing banner is printed with `println!` to the terminal only, so a
//!   startup ticket is never persisted here.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The log's file name inside the data directory.
pub const LOG_FILE: &str = "portty-host.log";

/// Size at which the log rotates to `portty-host.log.1`.
pub const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// Where the background host writes its log, for `portty-host status`.
pub fn log_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LOG_FILE)
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

/// The tracing layer that writes plain lines to `log`, next to the terminal one.
pub fn layer<S>(log: RotatingLog) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .fmt_fields(PlainFields::default())
        .with_writer(std::sync::Mutex::new(log))
}

/// The default span-field format under a type of its own.
///
/// fmt layers cache each span's formatted fields keyed by their field
/// formatter's TYPE, so two layers on the default type share one copy - made
/// by whichever layer saw the span first. That was the colourful terminal
/// layer, and its escape codes ended up in this file.
#[derive(Default)]
pub struct PlainFields(tracing_subscriber::fmt::format::DefaultFields);

impl<'writer> tracing_subscriber::fmt::FormatFields<'writer> for PlainFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: tracing_subscriber::fmt::format::Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        self.0.format_fields(writer, fields)
    }
}

/// An append-only log file that rotates once it reaches its size limit.
///
/// Wrapped in a `Mutex` it is a tracing `MakeWriter`. The fmt layer formats a
/// whole event before writing it, so rotation lands between lines.
pub struct RotatingLog {
    path: PathBuf,
    max_bytes: u64,
    file: Option<std::fs::File>,
    bytes: u64,
}

impl RotatingLog {
    /// Open (or continue) the log in `data_dir`.
    pub fn open(data_dir: &Path) -> std::io::Result<Self> {
        Self::open_with_limit(data_dir, MAX_LOG_BYTES)
    }

    fn open_with_limit(data_dir: &Path, max_bytes: u64) -> std::io::Result<Self> {
        portty_transport::secure::prepare_secret_dir(data_dir)?;
        let path = log_path(data_dir);
        let file = open_owner_only(&path, true)?;
        // A restarted daemon keeps appending, and the earlier run's bytes count.
        let bytes = file.metadata()?.len();
        Ok(Self {
            path,
            max_bytes,
            file: Some(file),
            bytes,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        // Closed before the rename: Windows will not move a file with an open handle.
        self.file = None;
        // A failed move (the file was deleted by hand, say) still starts a fresh
        // file below - staying bounded matters more than keeping the old lines.
        let _ = std::fs::rename(&self.path, rotated_path(&self.path));
        self.file = Some(open_owner_only(&self.path, false)?);
        self.bytes = 0;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.file.is_none() || (self.bytes > 0 && self.bytes + buf.len() as u64 > self.max_bytes)
        {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else {
            return Err(std::io::Error::other("log file is not open"));
        };
        let written = file.write(buf)?;
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

fn open_owner_only(path: &Path, append: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true);
    if append {
        options.append(true);
    } else {
        options.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 0600 from creation, and never written through a planted symlink.
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    // `mode` only applies to a new file; an older one is tightened here.
    portty_transport::secure::restrict_open_file_to_current_user(&file, path)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn a_reopened_log_appends_and_counts_what_is_there() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open_with_limit(dir.path(), 64).unwrap();
        log.write_all(b"first run\n").unwrap();
        drop(log);

        let mut log = RotatingLog::open_with_limit(dir.path(), 64).unwrap();
        assert_eq!(
            log.bytes, 10,
            "the earlier run's bytes count toward the limit"
        );
        log.write_all(b"second run\n").unwrap();
        assert_eq!(read(&log_path(dir.path())), "first run\nsecond run\n");
        assert!(!rotated_path(&log_path(dir.path())).exists());
    }

    #[test]
    fn the_log_rotates_at_its_limit_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        let mut log = RotatingLog::open_with_limit(dir.path(), 32).unwrap();
        for i in 0..100 {
            log.write_all(format!("line {i:03} ........\n").as_bytes())
                .unwrap();
        }
        let current = read(&path);
        let previous = read(&rotated_path(&path));
        assert!(
            current.len() <= 32,
            "current log is {} bytes",
            current.len()
        );
        assert!(
            previous.len() <= 32,
            "rotated log is {} bytes",
            previous.len()
        );
        assert!(current.ends_with("line 099 ........\n"), "{current:?}");
        assert!(previous.ends_with("line 098 ........\n"), "{previous:?}");
        // Exactly two files: rotation replaces `.log.1`, never adds `.log.2`.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn a_log_already_over_the_limit_rotates_on_the_next_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        std::fs::write(&path, "x".repeat(100)).unwrap();
        let mut log = RotatingLog::open_with_limit(dir.path(), 64).unwrap();
        log.write_all(b"fresh\n").unwrap();
        assert_eq!(read(&path), "fresh\n");
        assert_eq!(read(&rotated_path(&path)).len(), 100);
    }

    #[test]
    fn a_log_deleted_while_running_starts_over_at_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        let mut log = RotatingLog::open_with_limit(dir.path(), 16).unwrap();
        log.write_all(b"0123456789\n").unwrap();
        std::fs::remove_file(&path).unwrap();
        log.write_all(b"after delete\n").unwrap();
        assert_eq!(read(&path), "after delete\n");
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_owner_only_even_if_it_existed_open() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut log = RotatingLog::open_with_limit(dir.path(), 8).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "reopened log: {mode:o}");
        let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(dir_mode & 0o777, 0o700, "data dir: {dir_mode:o}");

        log.write_all(b"rotated now\n").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "fresh log after rotation: {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_never_written_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere.txt");
        std::fs::write(&elsewhere, "untouched").unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::os::unix::fs::symlink(&elsewhere, log_path(&data)).unwrap();

        assert!(RotatingLog::open_with_limit(&data, 64).is_err());
        assert_eq!(read(&elsewhere), "untouched");
    }

    #[test]
    fn tracing_lines_reach_the_file_without_colour_codes() {
        use tracing_subscriber::layer::SubscriberExt;
        let dir = tempfile::tempdir().unwrap();
        let log = RotatingLog::open(dir.path()).unwrap();
        // As in `main`: a coloured terminal layer first, then the file.
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(true)
                    .with_writer(std::io::sink),
            )
            .with(layer(log));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("endpoint", id = "0123456789");
            let _entered = span.enter();
            tracing::warn!(peer = "abc123", "phone reconnect refused");
        });
        let text = read(&log_path(dir.path()));
        assert!(text.contains("WARN"), "{text:?}");
        assert!(text.contains("phone reconnect refused"), "{text:?}");
        assert!(text.contains("peer=\"abc123\""), "{text:?}");
        assert!(text.contains("endpoint{id=\"0123456789\"}"), "{text:?}");
        assert!(!text.contains('\u{1b}'), "ANSI escape in the log: {text:?}");
    }
}
