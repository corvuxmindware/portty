//! Guard the committed Android settings that Play distribution depends on.

use std::fs;
use std::path::PathBuf;

fn tauri_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = tauri_dir().join(relative);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn configured_app_id() -> String {
    read("tauri.conf.json")
        .lines()
        .find_map(|line| line.trim().strip_prefix("\"identifier\": \""))
        .and_then(|value| value.split('"').next())
        .filter(|value| !value.is_empty())
        .expect("tauri.conf.json is missing identifier")
        .to_owned()
}

#[test]
fn manifest_declares_every_permission_a_feature_needs() {
    let manifest = read("gen/android/app/src/main/AndroidManifest.xml");

    for required in [
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.CAMERA",
        "android.permission.POST_NOTIFICATIONS",
        "com.google.firebase.MESSAGING_EVENT",
    ] {
        assert!(
            manifest.contains(required),
            "AndroidManifest.xml is missing {required}"
        );
    }
}

#[test]
fn main_activity_requests_the_android13_notification_prompt() {
    let identifier = configured_app_id();
    let source = format!(
        "gen/android/app/src/main/java/{}/MainActivity.kt",
        identifier.replace('.', "/")
    );
    let activity = read(&source);
    assert!(activity.contains(&format!("package {identifier}")));
    let gradle = read("gen/android/app/build.gradle.kts");
    assert!(gradle.contains(&format!("namespace = \"{identifier}\"")));
    assert!(gradle.contains(&format!("applicationId = \"{identifier}\"")));

    // The manifest entry alone shows nothing on Android 13+; the runtime ask is
    // the iOS `requestAuthorizationWithOptions` twin (push_glue.mm).
    assert!(
        activity.contains("Manifest.permission.POST_NOTIFICATIONS"),
        "MainActivity no longer requests POST_NOTIFICATIONS at runtime"
    );
    // The prompt must stay gated on Firebase being provisioned, so builds
    // without google-services.json never nag the user.
    assert!(
        activity.contains("FirebaseApp.getApps"),
        "the notification prompt must stay gated on an initialized FirebaseApp"
    );
}

#[test]
fn release_build_is_minified_signable_and_never_cleartext() {
    let gradle = read("gen/android/app/build.gradle.kts");

    assert!(gradle.contains("isMinifyEnabled = true"));
    // Cleartext is a debug-only override; the default must remain "false".
    assert!(gradle.contains(r#"manifestPlaceholders["usesCleartextTraffic"] = "false""#));
    // Release signing wiring (activated by a git-ignored key.properties).
    assert!(
        gradle.contains("key.properties"),
        "release signing wiring is gone (see packaging/ANDROID_BUILD_RUNBOOK.md)"
    );
    // Firebase must stay opt-in: applying the plugin unconditionally breaks
    // every build that has no google-services.json.
    assert!(
        gradle.contains(r#"if (file("google-services.json").exists())"#),
        "google-services plugin application must stay conditional"
    );
}

#[test]
fn tauri_config_pins_the_android_version_code() {
    let config = read("tauri.conf.json");

    // Tauri would otherwise derive 1000 from semver 0.1.0 forever; the pinned
    // code is what makes each Play upload installable over the previous one.
    // Bump it together with the iOS bundleVersion (and this assertion).
    assert!(
        config.contains("\"versionCode\": 1007"),
        "tauri.conf.json must pin bundle > android > versionCode"
    );
}

#[test]
fn android_launcher_sources_match_the_generated_project() {
    // Tauri keeps a source icon set and a generated Gradle resource set. If
    // they drift, a regeneration can silently restore an old launcher mark.
    for density in ["mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"] {
        for name in [
            "ic_launcher.png",
            "ic_launcher_round.png",
            "ic_launcher_foreground.png",
        ] {
            let source = tauri_dir()
                .join("icons/android")
                .join(format!("mipmap-{density}"))
                .join(name);
            let generated = tauri_dir()
                .join("gen/android/app/src/main/res")
                .join(format!("mipmap-{density}"))
                .join(name);
            assert_eq!(
                fs::read(&source).unwrap_or_else(|error| {
                    panic!("failed to read {}: {error}", source.display())
                }),
                fs::read(&generated).unwrap_or_else(|error| {
                    panic!("failed to read {}: {error}", generated.display())
                }),
                "{density}/{name} differs between source and generated Android icons"
            );
        }
    }
}

#[test]
fn mobile_components_do_not_use_platform_font_glyphs_as_icons() {
    let tauri = tauri_dir();
    let app_dir = tauri
        .parent()
        .expect("src-tauri must have the app directory as its parent");
    let fragile_glyphs = [
        "🔦", "🔓", "🔒", "🖥", "⚠", "⌨", "⏻", "⏏", "✎", "✕", "✓", "⇄", "⌁", "■", "●", "○", "◇",
        "⌕", "▣", "▾", "▦", "＋", "▶", "⏸", "⤓", "⌃", "⌄", "Δ",
    ];

    for component in [
        "App.tsx",
        "AgentView.tsx",
        "BiometricGate.tsx",
        "KeyBar.tsx",
        "QrScanner.tsx",
    ] {
        let path = app_dir.join("src").join(component);
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        for glyph in fragile_glyphs {
            assert!(
                !source.contains(glyph),
                "{component} uses platform-font glyph {glyph:?} as an icon; use src/Icon.tsx"
            );
        }
    }
}
