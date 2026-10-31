//! Bounded directory selection for phone-started sessions.
//!
//! **Agents** may choose a directory only WITHIN the one the daemon was launched
//! from (or `PORTTY_WORKSPACE`). That keeps the trust boundary exactly where it
//! already was - set on the laptop, at launch - while letting each session pick
//! something NARROWER than the root. A paired phone can never widen an agent's
//! reach; picking a subdirectory strictly shrinks its ACP file-access sandbox.
//!
//! **Terminals** may additionally choose among the [`TerminalRoot`]s this host
//! serves (see [`terminal_roots`]) - by default the workspace and the user's home.
//! That is not the same relaxation it would be for an agent: a shell can `cd`
//! anywhere its user can reach the moment it opens, so the roots add convenient
//! enumeration rather than reach, and a paired phone could already achieve the same
//! by opening a shell and running `ls`. The workspace bound stays exactly as strict
//! for agents, and `NewAgentSessionIn` cannot name a root at all - the confinement
//! that IS a sandbox boundary is enforced by the wire's shape, not by a check.
//!
//! Every path the phone sends is relative by construction (see
//! `RequestKind::ListWorkspaceDirs` and `ListDirsIn`), but nothing here trusts
//! that: the resolver re-checks the shape syntactically AND re-checks containment
//! after canonicalization, so a symlink pointing out of the chosen root fails even
//! though its textual path looked fine.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use portty_protocol::{TerminalRoot, WorkspaceScope};

/// Classify how broad a workspace root is.
///
/// [`resolve_within`] and `session::sandboxed_acp_path` confine every ACP file
/// read to this root, and they do it properly - canonical realpath, symlink
/// rejection, containment. What neither can judge is whether the root is worth
/// confining TO. Point it at the home directory and the sandbox still works
/// perfectly while bounding essentially nothing.
///
/// That was not hypothetical: every shipped service file set `PORTTY_WORKSPACE`
/// to the home directory, so the default `readonly` tier - which auto-approves
/// reads - silently meant "read anything I own" rather than "read this project".
/// The phone cannot see the root, so the host reports this and the phone refuses
/// blanket read approval on [`WorkspaceScope::Broad`].
///
/// `Broad` when the root contains the home directory (which covers the home
/// directory itself, `/Users`, `/home`, and `/`), and whenever the home
/// directory or the root cannot be resolved at all - an unknown root is not a
/// root anyone should grant blanket reads inside.
pub fn workspace_scope(root: &Path) -> WorkspaceScope {
    let Ok(root) = root.canonicalize() else {
        return WorkspaceScope::Broad;
    };
    // A filesystem root has no parent. Nothing narrower to say about it.
    if root.parent().is_none() {
        return WorkspaceScope::Broad;
    }
    let Some(home) = home_dir() else {
        return WorkspaceScope::Broad;
    };
    let Ok(home) = home.canonicalize() else {
        return WorkspaceScope::Broad;
    };
    // `home` inside `root` means root is home or an ancestor of it. Note the
    // direction: a project INSIDE home (`~/code/app`) is Project, which is the
    // normal and correct case.
    if home.starts_with(&root) {
        WorkspaceScope::Broad
    } else {
        WorkspaceScope::Project
    }
}

/// Env var that narrows which [`TerminalRoot`]s this host serves.
///
/// Unset means workspace + home, which is the default on purpose: the workspace
/// root could previously only be widened on the LAPTOP (`PORTTY_WORKSPACE`), and a
/// product whose premise is reaching a machine from your phone cannot require a
/// laptop-side env var to reach an ordinary folder.
///
/// Set it to a comma-separated list to restrict - in practice
/// `PORTTY_TERMINAL_ROOTS=workspace`, which turns home off. The workspace is
/// always served: it is the base every pre-v10 `rel` meant, and losing it would
/// break the picker rather than tighten it.
pub const TERMINAL_ROOTS_VAR: &str = "PORTTY_TERMINAL_ROOTS";

/// Which roots this host serves, workspace first.
pub fn terminal_roots() -> Vec<TerminalRoot> {
    terminal_roots_from(
        std::env::var(TERMINAL_ROOTS_VAR).ok().as_deref(),
        home_dir().is_some(),
    )
}

/// The root-set decision, as a pure function.
///
/// `setting` is [`TERMINAL_ROOTS_VAR`]'s value (`None` when unset).
/// `home_available` is whether the platform will name a home directory - an
/// unresolvable home is not a root anyone can browse.
///
/// Split from [`terminal_roots`] so the policy is testable without mutating the
/// process-wide environment, which every other test in this binary shares.
///
/// An unrecognized token neither enables nor disables anything; it simply is not a
/// root. That stops a typo (`PORTTY_TERMINAL_ROOTS=hoem`) reading as "serve
/// everything", which is the direction permissive-by-omission fails in.
fn terminal_roots_from(setting: Option<&str>, home_available: bool) -> Vec<TerminalRoot> {
    let mut roots = vec![TerminalRoot::Workspace];
    let allow_home = match setting {
        Some(raw) => raw
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("home")),
        None => true,
    };
    if allow_home && home_available {
        roots.push(TerminalRoot::Home);
    }
    roots
}

/// The absolute path of a root, or `None` when this host does not serve it.
///
/// The single gate for every rooted request: a root the operator turned off, or one
/// the platform cannot resolve, has no path - so listing and spawning both fail
/// closed on the same check rather than each remembering to make it.
pub fn terminal_root_path(root: TerminalRoot) -> Option<PathBuf> {
    if !terminal_roots().contains(&root) {
        return None;
    }
    match root {
        TerminalRoot::Workspace => Some(crate::iroh_serve::workspace_dir()),
        TerminalRoot::Home => home_dir(),
    }
}

/// The user's home directory, or `None` if the platform will not say.
///
/// `directories` is already a dependency for the app-data dir; `UserDirs` is its
/// home-dir accessor. Returning `None` rather than guessing is deliberate -
/// [`workspace_scope`] treats "cannot tell" as `Broad`.
fn home_dir() -> Option<PathBuf> {
    directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
}

/// Cap on entries in one listing. A directory with tens of thousands of children
/// would otherwise blow the frame budget and produce a list nobody can scroll.
pub const MAX_WORKSPACE_DIR_ENTRIES: usize = 500;

#[derive(Debug, PartialEq, Eq)]
pub enum WorkspaceError {
    /// The phone sent an absolute path, a Windows prefix, or a `..` component.
    NotRelative,
    /// Resolved cleanly but landed outside the root - the symlink case.
    Escapes,
    NotADirectory,
    Io(String),
}

impl fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Deliberately vague about the root's location: the phone is
            // authenticated, but an error string is not the place to disclose
            // host filesystem layout.
            Self::NotRelative => f.write_str("path must be relative to the workspace"),
            Self::Escapes => f.write_str("path is outside the workspace"),
            Self::NotADirectory => f.write_str("path is not a directory"),
            Self::Io(message) => write!(f, "{message}"),
        }
    }
}

/// Normalize a phone-supplied relative path to `a/b` form.
///
/// Rejects `..` outright rather than resolving it. A legitimate `a/../b` would
/// be harmless, but the picker only ever descends - it sends a SHORTER `rel` to
/// go up - so `..` never appears in honest traffic, and refusing it removes a
/// whole class of normalization bugs before any filesystem call happens.
pub fn normalize_rel(rel: &str) -> Result<String, WorkspaceError> {
    let path = Path::new(rel);
    if path.is_absolute() {
        return Err(WorkspaceError::NotRelative);
    }
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                parts.push(part.to_str().ok_or(WorkspaceError::NotRelative)?);
            }
            // `.` is meaningless noise; everything else is an escape attempt or
            // a platform prefix that has no business on this wire.
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceError::NotRelative);
            }
        }
    }
    Ok(parts.join("/"))
}

/// Resolve `rel` against `root`, guaranteeing the result is inside it.
///
/// `root` is canonicalized here rather than assumed: the caller's copy may still
/// contain symlinks, and `starts_with` on a half-resolved root would compare two
/// different spellings of the same tree and reject valid paths.
pub fn resolve_within(root: &Path, rel: &str) -> Result<PathBuf, WorkspaceError> {
    let rel = normalize_rel(rel)?;
    let root = root
        .canonicalize()
        .map_err(|error| WorkspaceError::Io(error.to_string()))?;
    let resolved = root
        .join(&rel)
        .canonicalize()
        .map_err(|error| WorkspaceError::Io(error.to_string()))?;
    // The authoritative check. canonicalize() resolved every symlink, so a link
    // inside the tree pointing out of it lands here and is refused.
    if !resolved.starts_with(&root) {
        return Err(WorkspaceError::Escapes);
    }
    if !resolved.is_dir() {
        return Err(WorkspaceError::NotADirectory);
    }
    Ok(resolved)
}

/// The spelling of an absolute path to hand to ANOTHER program: a shell's
/// working directory, or the directory an agent is asked about.
///
/// [`resolve_within`] and every other `canonicalize` in the host produce, on
/// Windows, the verbatim form - `\\?\C:\w\app`, or `\\?\UNC\server\share\app` on
/// a network share. Windows' own file APIs accept it; programs often do not.
/// cmd.exe reads a working directory that starts `\\` as a UNC path it cannot
/// use, prints "UNC paths are not supported. Defaulting to Windows directory."
/// and starts in `C:\Windows` instead. That was every phone terminal on Windows,
/// because portable-pty passes the directory to Windows exactly as given.
/// (`std::process::Command` strips the prefix itself when it safely can, by
/// much the same rules as these.)
///
/// Rewritten only when the plain spelling provably names the same place (see
/// [`verbatim::plain`]); anything else comes back unchanged, which is no
/// worse than before. A network share stays a UNC path either way, and cmd.exe
/// refuses those too - other programs do not. Unix has no verbatim form, so this
/// is the identity there: a Unix path that starts `\\?\` is an ordinary name.
///
/// A spelling for the OS boundary only. Containment checks keep comparing the
/// canonical form, so nothing here is ever an input to `starts_with`.
pub fn plain_spelling(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
        // Through UTF-16, not `to_string_lossy`: a Windows path need not be
        // valid Unicode, and the lossy form would hand a program a path with
        // U+FFFD where its real characters used to be.
        let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if let Some(plain) = verbatim::plain(&wide) {
            return PathBuf::from(OsString::from_wide(&plain));
        }
    }
    path.to_path_buf()
}

/// The rules for undoing the verbatim prefix, on raw UTF-16.
///
/// Platform-independent on purpose, so they are tested on every OS. Outside
/// tests only [`plain_spelling`] uses them, and only on Windows - hence the
/// `dead_code` allowance everywhere else.
#[cfg_attr(not(windows), allow(dead_code))]
mod verbatim {
    /// Longest plain directory this will produce, in UTF-16 units.
    ///
    /// Windows limits a working directory to `MAX_PATH - 2` characters unless the
    /// machine opted in to long paths; the verbatim form is exempt. A longer path
    /// keeps its verbatim spelling rather than become one Windows may refuse.
    pub(super) const MAX_PLAIN_DIR_UNITS: usize = 258;

    const BACKSLASH: u16 = b'\\' as u16;
    /// `\\?\`
    const PREFIX: [u16; 4] = [BACKSLASH, BACKSLASH, b'?' as u16, BACKSLASH];
    /// `UNC\`, right after the prefix. Upper case only: that is what
    /// `canonicalize` produces, and anything else is left alone.
    const UNC: [u16; 4] = [b'U' as u16, b'N' as u16, b'C' as u16, BACKSLASH];
    /// Characters Win32 refuses inside a name (control characters are checked
    /// separately).
    const FORBIDDEN_IN_NAME: &[u8] = b"<>:\"/\\|?*";

    /// The plain spelling of a Windows verbatim path - or `None` when it has none
    /// that means the same thing.
    ///
    /// - `\\?\C:\x` becomes `C:\x`: a drive letter, a colon, then the root.
    /// - `\\?\UNC\server\share\x` becomes `\\server\share\x`.
    /// - Everything else is `None`: a path that is not verbatim, the `\\.\`
    ///   device namespace, `\\?\Volume{...}` and `\\?\GLOBALROOT` (no plain
    ///   form), and a bare `\\?\C:`, whose plain form would be the
    ///   drive-RELATIVE `C:`.
    ///
    /// Verbatim paths skip Win32 normalization, so they can name things a plain
    /// path cannot: a component with a trailing dot or space (normalization
    /// strips it), a reserved device name such as `NUL`, `CON` or `COM1` (it
    /// would open the device), `.` or `..` (it would be resolved), or a character
    /// Win32 rejects. Any of those, an empty component, or a result too long for
    /// a working directory keeps the verbatim spelling.
    pub(super) fn plain(wide: &[u16]) -> Option<Vec<u16>> {
        let rest = wide.strip_prefix(&PREFIX[..])?;
        let plain = if let Some(tail) = rest.strip_prefix(&UNC[..]) {
            // `server\share` first, then the path inside the share.
            let mut parts = tail.split(|&c| c == BACKSLASH);
            let server = parts.next()?;
            let share = parts.next()?;
            if !component_ok(server) || !component_ok(share) || !components_ok(parts) {
                return None;
            }
            let mut plain = vec![BACKSLASH, BACKSLASH];
            plain.extend_from_slice(tail);
            plain
        } else {
            // `C:\` and then the path. The root backslash is required: without
            // it, `C:x` would mean "x in drive C's current directory".
            let tail = match rest {
                [letter, colon, root, tail @ ..]
                    if u8::try_from(*letter).is_ok_and(|b| b.is_ascii_alphabetic())
                        && *colon == u16::from(b':')
                        && *root == BACKSLASH =>
                {
                    tail
                }
                _ => return None,
            };
            if !tail.is_empty() && !components_ok(tail.split(|&c| c == BACKSLASH)) {
                return None;
            }
            rest.to_vec()
        };
        (plain.len() <= MAX_PLAIN_DIR_UNITS).then_some(plain)
    }

    /// Every component survives Win32 normalization unchanged. One trailing
    /// empty component (a trailing backslash) is allowed; any other is not.
    fn components_ok<'a>(parts: impl Iterator<Item = &'a [u16]>) -> bool {
        let mut parts = parts.peekable();
        while let Some(part) = parts.next() {
            if part.is_empty() && parts.peek().is_none() {
                return true;
            }
            if !component_ok(part) {
                return false;
            }
        }
        true
    }

    /// One path component that means the same thing with or without `\\?\`.
    fn component_ok(part: &[u16]) -> bool {
        // Empty is not a name; `.`, `..` and any other trailing dot or space
        // would be resolved or stripped by normalization.
        let Some(&last) = part.last() else {
            return false;
        };
        if last == u16::from(b'.') || last == u16::from(b' ') {
            return false;
        }
        let forbidden =
            |c: u16| c < 0x20 || u8::try_from(c).is_ok_and(|b| FORBIDDEN_IN_NAME.contains(&b));
        !part.iter().any(|&c| forbidden(c)) && !is_reserved_device_name(part)
    }

    /// `CON`, `NUL`, `COM1` and the rest, matched the way Windows matches them:
    /// ignoring case, and ignoring everything from the first dot (`nul.txt` is
    /// still the device) along with any spaces before it.
    fn is_reserved_device_name(part: &[u16]) -> bool {
        let stem_end = part
            .iter()
            .position(|&c| c == u16::from(b'.'))
            .unwrap_or(part.len());
        let stem = String::from_utf16_lossy(&part[..stem_end]);
        let stem = stem.trim_end_matches(' ').to_ascii_uppercase();
        if matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) {
            return true;
        }
        // COM0-9 and LPT0-9, plus the superscript digits Windows also treats as
        // port numbers (COM¹, LPT³).
        ["COM", "LPT"].iter().any(|port| {
            stem.strip_prefix(port).is_some_and(|digit| {
                let mut chars = digit.chars();
                matches!(
                    (chars.next(), chars.next()),
                    (Some('0'..='9' | '¹' | '²' | '³'), None)
                )
            })
        })
    }
}

/// Immediate child directory names of `rel`, sorted and capped.
///
/// Only directories, and only ones that survive [`resolve_within`] themselves -
/// listing a symlinked directory that selection would later refuse is a trap.
/// Files are never listed: the picker chooses a working directory, and file
/// names in a workspace can be sensitive on their own.
///
/// Dot-directories are skipped. `.git`, `.venv` and friends are never the
/// directory you want an agent to treat as its project root, and including them
/// buries the ones you do want.
pub fn list_dirs(root: &Path, rel: &str) -> Result<(String, Vec<String>), WorkspaceError> {
    let normalized = normalize_rel(rel)?;
    let dir = resolve_within(root, &normalized)?;
    let mut names: Vec<String> = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|error| WorkspaceError::Io(error.to_string()))?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            // One unreadable entry must not fail the whole listing.
            Err(_) => continue,
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue, // non-UTF-8 name: unrepresentable on the wire
        };
        if name.starts_with('.') {
            continue;
        }
        // file_type() does not follow symlinks; is_dir() on the path does. Use
        // the following form so a symlinked project directory still appears,
        // then confirm it stays inside the tree.
        if !entry.path().is_dir() {
            continue;
        }
        let child_rel = if normalized.is_empty() {
            name.clone()
        } else {
            format!("{normalized}/{name}")
        };
        if resolve_within(root, &child_rel).is_err() {
            continue;
        }
        names.push(name);
    }
    names.sort();
    names.truncate(MAX_WORKSPACE_DIR_ENTRIES);
    Ok((normalized, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default is workspace + home. That is the whole point of v10: the
    /// workspace could only be widened on the laptop, which is useless to someone
    /// holding a phone.
    #[test]
    fn home_is_served_by_default_and_turned_off_by_the_env_var() {
        assert_eq!(
            terminal_roots_from(None, true),
            vec![TerminalRoot::Workspace, TerminalRoot::Home]
        );

        // The documented restriction.
        assert_eq!(
            terminal_roots_from(Some("workspace"), true),
            vec![TerminalRoot::Workspace]
        );
        // Order and spacing are the operator's business, not ours.
        assert_eq!(
            terminal_roots_from(Some(" HOME , workspace "), true),
            vec![TerminalRoot::Workspace, TerminalRoot::Home]
        );

        // A typo must not read as "serve everything" - it names no root, so home
        // stays off. Permissive-by-omission is the failure direction that matters.
        assert_eq!(
            terminal_roots_from(Some("hoem"), true),
            vec![TerminalRoot::Workspace]
        );
        // An empty setting is a setting: it names nothing.
        assert_eq!(
            terminal_roots_from(Some(""), true),
            vec![TerminalRoot::Workspace]
        );

        // A home the platform will not name is not offered even when allowed.
        assert_eq!(
            terminal_roots_from(None, false),
            vec![TerminalRoot::Workspace]
        );

        // The workspace is never lost - it is the base every pre-v10 rel meant.
        for setting in [
            None,
            Some("workspace"),
            Some("home"),
            Some(""),
            Some("junk"),
        ] {
            assert!(
                terminal_roots_from(setting, true).contains(&TerminalRoot::Workspace),
                "workspace must always be served ({setting:?})"
            );
        }
    }

    /// The gate both rooted handlers share: no path means refused. A root that is
    /// off must not fall back to one that is on.
    #[test]
    fn a_disabled_root_resolves_to_no_path() {
        // `terminal_root_path` consults the live env, so assert the property that
        // holds either way: whatever the set is, a root outside it has no path.
        let served = terminal_roots();
        assert!(served.contains(&TerminalRoot::Workspace));
        for root in [TerminalRoot::Workspace, TerminalRoot::Home] {
            if !served.contains(&root) {
                assert!(
                    terminal_root_path(root).is_none(),
                    "{root:?} is not served, so it must have no path"
                );
            }
        }
    }

    fn tree() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("project-portty/crates")).unwrap();
        std::fs::create_dir(root.path().join("other-project")).unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join("README.md"), b"x").unwrap();
        root
    }

    #[test]
    fn normalizes_and_rejects_escapes() {
        assert_eq!(normalize_rel("").unwrap(), "");
        assert_eq!(normalize_rel("a/b").unwrap(), "a/b");
        assert_eq!(normalize_rel("./a//b/").unwrap(), "a/b");
        assert_eq!(normalize_rel(".."), Err(WorkspaceError::NotRelative));
        assert_eq!(normalize_rel("a/../../b"), Err(WorkspaceError::NotRelative));
        assert_eq!(normalize_rel("/etc"), Err(WorkspaceError::NotRelative));
    }

    #[test]
    fn resolves_only_inside_the_root() {
        let root = tree();
        let inside = resolve_within(root.path(), "project-portty").unwrap();
        assert!(inside.ends_with("project-portty"));
        // The root itself is a valid choice.
        assert!(resolve_within(root.path(), "").is_ok());
        // A file is not.
        assert_eq!(
            resolve_within(root.path(), "README.md"),
            Err(WorkspaceError::NotADirectory)
        );
        assert_eq!(
            resolve_within(root.path(), "../.."),
            Err(WorkspaceError::NotRelative)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_tree_is_refused() {
        let root = tree();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        // Textually it is a plain relative name; only canonicalization catches it.
        assert_eq!(
            resolve_within(root.path(), "escape"),
            Err(WorkspaceError::Escapes)
        );
        // ...and it must not be offered in the listing either.
        let (_, names) = list_dirs(root.path(), "").unwrap();
        assert!(!names.contains(&"escape".to_string()), "got {names:?}");
    }

    /// A project the user chose is `Project` even though it lives inside home -
    /// that is the normal case and must not be misread as broad.
    #[test]
    fn a_project_directory_inside_home_is_project_scope() {
        let Some(home) = home_dir().and_then(|h| h.canonicalize().ok()) else {
            eprintln!("skipping: no resolvable home directory on this platform");
            return;
        };
        let root = tempfile::tempdir_in(&home).expect("a temp dir inside home");
        assert_eq!(workspace_scope(root.path()), WorkspaceScope::Project);
    }

    /// The bug this exists for: the shipped service files pointed the sandbox
    /// root at the home directory, so confinement bounded everything the user
    /// owns.
    #[test]
    fn the_home_directory_itself_is_broad() {
        let Some(home) = home_dir() else {
            eprintln!("skipping: no resolvable home directory on this platform");
            return;
        };
        assert_eq!(workspace_scope(&home), WorkspaceScope::Broad);
    }

    /// Any ancestor of home is broad too - `/`, `/Users`, `/home`.
    #[test]
    fn an_ancestor_of_home_is_broad() {
        let Some(home) = home_dir().and_then(|h| h.canonicalize().ok()) else {
            eprintln!("skipping: no resolvable home directory on this platform");
            return;
        };
        let mut ancestor = home.parent();
        while let Some(path) = ancestor {
            assert_eq!(
                workspace_scope(path),
                WorkspaceScope::Broad,
                "{} contains home and must be Broad",
                path.display()
            );
            ancestor = path.parent();
        }
    }

    /// "Cannot tell" must never read as the permissive answer.
    #[test]
    fn an_unresolvable_root_is_broad() {
        assert_eq!(
            workspace_scope(Path::new("/definitely/not/here/at/all")),
            WorkspaceScope::Broad
        );
    }

    #[test]
    fn lists_only_visible_child_directories() {
        let root = tree();
        let (rel, names) = list_dirs(root.path(), "").unwrap();
        assert_eq!(rel, "");
        assert_eq!(names, vec!["other-project", "project-portty"]);
        // Files and dot-dirs are absent; nesting works.
        let (rel, names) = list_dirs(root.path(), "project-portty").unwrap();
        assert_eq!(rel, "project-portty");
        assert_eq!(names, vec!["crates"]);
    }

    #[test]
    fn listing_a_bad_path_fails_rather_than_falling_back_to_the_root() {
        let root = tree();
        assert_eq!(
            list_dirs(root.path(), ".."),
            Err(WorkspaceError::NotRelative)
        );
        assert!(matches!(
            list_dirs(root.path(), "nope"),
            Err(WorkspaceError::Io(_))
        ));
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// `verbatim::plain` on a `&str`, for readable assertions.
    fn plain(text: &str) -> Option<String> {
        verbatim::plain(&wide(text)).map(|units| String::from_utf16(&units).unwrap())
    }

    /// The two shapes `canonicalize` produces on Windows lose their prefix, and
    /// nothing else about them changes.
    #[test]
    fn verbatim_drive_and_unc_paths_get_their_plain_spelling() {
        assert_eq!(plain(r"\\?\C:\w\app").as_deref(), Some(r"C:\w\app"));
        assert_eq!(plain(r"\\?\C:\").as_deref(), Some(r"C:\"));
        assert_eq!(
            plain(r"\\?\d:\Projects\portty\").as_deref(),
            Some(r"d:\Projects\portty\")
        );
        assert_eq!(
            plain(r"\\?\C:\Users\Zoë\my app").as_deref(),
            Some(r"C:\Users\Zoë\my app")
        );
        assert_eq!(
            plain(r"\\?\UNC\server\share\x").as_deref(),
            Some(r"\\server\share\x")
        );
        assert_eq!(
            plain(r"\\?\UNC\server\share").as_deref(),
            Some(r"\\server\share")
        );
    }

    /// Anything that is not one of those two shapes is left exactly as it is.
    #[test]
    fn paths_that_are_not_verbatim_drive_or_unc_are_left_alone() {
        for untouched in [
            r"C:\w\app",
            r"\\server\share\x",
            "/home/me/app",
            "",
            r"\\?\",
            // Its plain form would be the drive-RELATIVE `C:`.
            r"\\?\C:",
            r"\\?\C:x",
            r"\\?\1:\x",
            // The device namespace, and verbatim forms with no plain spelling.
            r"\\.\C:\x",
            r"\\?\Volume{1b3b1146-4076-11e3-8b1b-806e6f6e6963}\x",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\x",
            // Only the spelling `canonicalize` itself produces.
            r"\\?\unc\server\share\x",
            // A UNC path needs a server AND a share.
            r"\\?\UNC\server",
            r"\\?\UNC\\share\x",
            // These would turn into the `\\.\` device namespace or back into a
            // verbatim path once the prefix is gone.
            r"\\?\UNC\.\pipe\x",
            r"\\?\UNC\?\C:\x",
        ] {
            assert_eq!(plain(untouched), None, "{untouched:?} must stay as it is");
        }
    }

    /// A component a plain path cannot express keeps the verbatim spelling:
    /// dropping the prefix would quietly change what the path names.
    #[test]
    fn names_a_plain_path_would_reinterpret_keep_the_prefix() {
        for verbatim_only in [
            r"\\?\C:\w\trailing.",
            r"\\?\C:\w\trailing ",
            r"\\?\C:\w\..\x",
            r"\\?\C:\w\.\x",
            r"\\?\C:\w\\x",
            r"\\?\C:\w/x",
            r"\\?\C:\w\a:b",
            r"\\?\C:\w\NUL",
            r"\\?\C:\w\nul.txt",
            r"\\?\C:\w\con .txt",
            r"\\?\C:\w\COM1",
            r"\\?\C:\w\lpt9.log",
            r"\\?\C:\w\COM¹",
            r"\\?\C:\w\CONIN$",
            r"\\?\UNC\server\share\aux",
        ] {
            assert_eq!(
                plain(verbatim_only),
                None,
                "{verbatim_only:?} only means what it says with the prefix"
            );
        }
        // Near misses are ordinary names and DO get the plain spelling.
        for ordinary in [
            r"\\?\C:\w\COM10",
            r"\\?\C:\w\console",
            r"\\?\C:\w\nullable",
            r"\\?\C:\w\LPT",
            r"\\?\C:\w\.git",
            r"\\?\C:\w\a.b.c",
        ] {
            assert!(
                plain(ordinary).is_some(),
                "{ordinary:?} is an ordinary name"
            );
        }
    }

    /// A plain path longer than a working directory may be keeps its prefix:
    /// the verbatim form is the one that still works at that length.
    #[test]
    fn a_path_too_long_for_a_working_directory_keeps_the_prefix() {
        let longest = verbatim::MAX_PLAIN_DIR_UNITS;
        let fits = format!(r"\\?\C:\{}", "a".repeat(longest - 3));
        assert_eq!(plain(&fits).map(|p| p.len()), Some(longest));
        let too_long = format!(r"\\?\C:\{}", "a".repeat(longest - 2));
        assert_eq!(plain(&too_long), None);
    }

    /// Windows names need not be valid Unicode. The rewrite works on raw UTF-16,
    /// so an unpaired surrogate comes through untouched instead of as U+FFFD.
    #[test]
    fn a_name_that_is_not_valid_unicode_survives_unchanged() {
        let mut path = wide(r"\\?\C:\w\");
        path.push(0xD800);
        path.extend(wide("x"));
        let mut want = wide(r"C:\w\");
        want.push(0xD800);
        want.extend(wide("x"));
        assert_eq!(verbatim::plain(&path), Some(want));
    }

    /// Off Windows the spelling is the path itself - even one that looks
    /// verbatim, which on Unix is just an unusual name.
    #[cfg(not(windows))]
    #[test]
    fn plain_spelling_is_the_identity_off_windows() {
        for path in [r"\\?\C:\w\app", "/home/me/app"] {
            assert_eq!(plain_spelling(Path::new(path)), Path::new(path));
        }
    }

    /// On a real directory: `canonicalize` hands back the verbatim form, and its
    /// plain spelling has no prefix yet still names the very same directory.
    /// (Whether a shell then starts there is pinned end to end, through ConPTY,
    /// in `session`.)
    #[cfg(windows)]
    #[test]
    fn a_canonical_directory_gets_a_plain_spelling_of_the_same_place() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        assert!(
            canonical.to_string_lossy().starts_with(r"\\?\"),
            "canonicalize is verbatim on Windows: {canonical:?}"
        );
        let plain = plain_spelling(&canonical);
        assert!(!plain.to_string_lossy().starts_with(r"\\"), "{plain:?}");
        assert_eq!(
            plain.canonicalize().unwrap(),
            canonical,
            "a different spelling of the same directory"
        );
    }
}
