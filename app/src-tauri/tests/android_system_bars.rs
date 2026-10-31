//! Guard Portty's Android system bars. The UI is always black, so the status-
//! and navigation-bar icons must stay light whatever the phone's system theme,
//! and nothing may flash white before the web view draws.

use std::fs;
use std::path::PathBuf;

const MAIN_ACTIVITY: &str =
    "gen/android/app/src/main/java/org/example/portty/MainActivity.kt";
const RES_DIR: &str = "gen/android/app/src/main/res";

fn tauri_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = tauri_dir().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

/// Kotlin source without its comment lines, so prose can't satisfy a check.
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            !(line.starts_with("//") || line.starts_with("/*") || line.starts_with('*'))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The arguments of MainActivity's one `enableEdgeToEdge(...)` call.
fn edge_to_edge_arguments(activity: &str) -> &str {
    let call = "enableEdgeToEdge(";
    let calls: Vec<usize> = activity.match_indices(call).map(|(at, _)| at).collect();
    assert_eq!(
        calls.len(),
        1,
        "MainActivity must call enableEdgeToEdge exactly once"
    );
    let start = calls[0] + call.len();
    let mut depth = 1;
    for (offset, character) in activity[start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &activity[start..start + offset];
                }
            }
            _ => {}
        }
    }
    panic!("MainActivity's enableEdgeToEdge( call is never closed")
}

#[test]
fn main_activity_keeps_both_bar_icons_light() {
    let activity = code_only(&read(MAIN_ACTIVITY));
    let arguments = edge_to_edge_arguments(&activity);

    // The default styles (SystemBarStyle.auto) follow the system theme: dark
    // icons in light mode, invisible on the black UI, plus a light scrim behind
    // 3-button navigation. dark() keeps both bars' icons light, scrim off.
    assert_eq!(
        arguments.matches("SystemBarStyle.dark(").count(),
        2,
        "enableEdgeToEdge must give the status bar AND the navigation bar \
         SystemBarStyle.dark(...); got ({arguments})"
    );
    for theme_following in ["SystemBarStyle.auto(", "SystemBarStyle.light("] {
        assert!(
            !activity.contains(theme_following),
            "MainActivity must not use {theme_following}...): Portty is black in both themes"
        );
    }
}

/// `(directory, contents)` of every `res/values*/themes.xml`.
fn theme_variants() -> Vec<(String, String)> {
    let res = tauri_dir().join(RES_DIR);
    let mut variants = Vec::new();
    for entry in fs::read_dir(&res)
        .unwrap_or_else(|error| panic!("failed to list {}: {error}", res.display()))
    {
        let directory = entry.expect("readable res/ entry").path();
        let name = directory
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        let themes = directory.join("themes.xml");
        if name.starts_with("values") && themes.is_file() {
            let contents = fs::read_to_string(&themes)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", themes.display()));
            variants.push((name, contents));
        }
    }
    variants.sort();
    variants
}

/// The text between `<{tag} name="{name}"...>` and `</{tag}>`.
fn named_element<'a>(xml: &'a str, tag: &str, name: &str) -> Option<&'a str> {
    let open = xml.find(&format!(r#"<{tag} name="{name}""#))?;
    let body = &xml[open..];
    let body = &body[body.find('>')? + 1..];
    Some(body[..body.find(&format!("</{tag}>"))?].trim())
}

/// Whether an Android colour value is opaque black: a `#RGB`/`#ARGB`/`#RRGGBB`/
/// `#AARRGGBB` literal, the platform's black, or an app `@color/` that is.
fn is_black(value: &str) -> bool {
    if value == "@android:color/black" {
        return true;
    }
    if let Some(name) = value.strip_prefix("@color/") {
        let colors = read(&format!("{RES_DIR}/values/colors.xml"));
        return named_element(&colors, "color", name).is_some_and(is_black);
    }
    matches!(
        value.to_ascii_lowercase().as_str(),
        "#000" | "#f000" | "#000000" | "#ff000000"
    )
}

#[test]
fn every_app_theme_variant_starts_black_with_light_bar_icons() {
    let manifest = read("gen/android/app/src/main/AndroidManifest.xml");
    assert!(
        manifest.contains(r#"android:theme="@style/Theme.portty_app""#),
        "the app no longer uses Theme.portty_app; point these checks at its theme"
    );

    let variants = theme_variants();
    for expected in ["values", "values-night"] {
        assert!(
            variants.iter().any(|(name, _)| name == expected),
            "res/{expected}/themes.xml is missing"
        );
    }
    for (variant, themes) in &variants {
        let theme = named_element(themes, "style", "Theme.portty_app")
            .unwrap_or_else(|| panic!("res/{variant}/themes.xml has no Theme.portty_app"));
        // Shown before the web view draws (and as the Android 12+ splash), and
        // the bars of the start-up window before Android 12.
        for colour in [
            "android:windowBackground",
            "android:statusBarColor",
            "android:navigationBarColor",
        ] {
            let value = named_element(theme, "item", colour).unwrap_or_default();
            assert!(
                is_black(value),
                "res/{variant}/themes.xml: {colour} must be black, got {value:?}"
            );
        }
        for light_icons_flag in [
            "android:windowLightStatusBar",
            "android:windowLightNavigationBar",
        ] {
            assert_eq!(
                named_element(theme, "item", light_icons_flag),
                Some("false"),
                "res/{variant}/themes.xml: {light_icons_flag} must be false (light icons)"
            );
        }
    }
}

#[test]
fn every_tauri_window_paints_black_before_the_page_loads() {
    let config: serde_json::Value =
        serde_json::from_str(&read("tauri.conf.json")).expect("tauri.conf.json is valid JSON");
    let windows = config["app"]["windows"]
        .as_array()
        .expect("tauri.conf.json declares app.windows");
    assert!(!windows.is_empty(), "tauri.conf.json declares no window");

    for window in windows {
        // Wry paints the web view with this until the page draws (on Android
        // WebView.setBackgroundColor); the default is white.
        assert_eq!(
            window["backgroundColor"], "#000000",
            "window {} must set backgroundColor #000000",
            window["title"]
        );
    }
}
