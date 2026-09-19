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
}
