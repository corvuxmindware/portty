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

/// The `android:configChanges` flags declared on `<activity android:name=name>`.
fn activity_config_changes(manifest: &str, name: &str) -> Vec<String> {
    let activity = manifest
        .split("<activity")
        .skip(1)
        .find(|element| element.contains(&format!(r#"android:name="{name}""#)))
        .unwrap_or_else(|| panic!("AndroidManifest.xml declares no {name} activity"));
    let value = activity
        .split(r#"android:configChanges=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("{name} declares no android:configChanges"));
    value
        .split('|')
        .map(|flag| flag.trim().to_owned())
        .collect()
}

#[test]
fn main_activity_handles_configuration_changes_in_place() {
    let manifest = read("gen/android/app/src/main/AndroidManifest.xml");
    let handled = activity_config_changes(&manifest, ".MainActivity");

    // Any change not listed re-creates MainActivity, which Tauri cannot follow
    // (MainActivity restarts the whole app instead). Font size, display size,
    // bold text, and RTL used to abort the process here.
    for required in [
        "orientation",
        "keyboardHidden",
        "keyboard",
        "screenSize",
        "smallestScreenSize",
        "screenLayout",
        "locale",
        "layoutDirection",
        "uiMode",
        "fontScale",
        "fontWeightAdjustment",
        "density",
        "colorMode",
        "mcc",
        "mnc",
        "navigation",
        "touchscreen",
        "grammaticalGender",
    ] {
        assert!(
            handled.iter().any(|flag| flag == required),
            "MainActivity configChanges is missing {required}: {handled:?}"
        );
    }

    // A live WebView reads the font scale only when it is created, so handling
    // fontScale in place means passing a changed scale on to it.
    let activity = read("gen/android/app/src/main/java/org/example/portty/MainActivity.kt");
    assert!(
        activity.contains("newConfig.fontScale") && activity.contains("settings.textZoom"),
        "MainActivity handles fontScale itself, so it must update the WebView text zoom"
    );
}

#[test]
fn a_second_main_activity_restarts_the_app() {
    let activity = read("gen/android/app/src/main/java/org/example/portty/MainActivity.kt");

    // Tauri's runtime stays bound to the first Activity of a process (stale
    // plugins, no WebView for a new Activity id), so a re-created MainActivity
    // must start a fresh process rather than run half-broken.
    assert!(
        activity.contains("Intent.makeRestartActivityTask"),
        "a re-created MainActivity must reopen the app in a fresh task"
    );
    assert!(
        activity.contains("Process.killProcess(Process.myPid())"),
        "a re-created MainActivity must end the process that owns the stale runtime"
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
fn no_app_data_leaves_the_phone_by_backup_or_transfer() {
    let rules = read("gen/android/app/src/main/res/xml/data_extraction_rules.xml");
    let manifest = read("gen/android/app/src/main/AndroidManifest.xml");

    assert!(manifest.contains(r#"android:allowBackup="false""#));
    assert!(manifest.contains(r#"android:dataExtractionRules="@xml/data_extraction_rules""#));

    // Tauri's data dir is the `root` domain, so leaving that one out used to let
    // device-to-device transfer copy host names, approval rules and the wake key
    // to a new phone. allowBackup="false" does not stop that transfer on 12+.
    for section in ["cloud-backup", "device-transfer"] {
        let body = rules
            .split(&format!("<{section}>"))
            .nth(1)
            .and_then(|rest| rest.split(&format!("</{section}>")).next())
            .unwrap_or_else(|| panic!("data_extraction_rules.xml has no <{section}> section"));
        assert!(
            !body.contains("<include"),
            "<{section}> must not include anything back"
        );
        for domain in [
            "root",
            "file",
            "database",
            "sharedpref",
            "external",
            "device_root",
            "device_file",
            "device_database",
            "device_sharedpref",
        ] {
            assert!(
                body.contains(&format!(r#"<exclude domain="{domain}" />"#)),
                "<{section}> must exclude the {domain} domain"
            );
        }
    }
}

#[test]
fn tauri_config_pins_the_android_version_code() {
    let config = read("tauri.conf.json");

    // Tauri would otherwise derive 1000 from semver 0.1.0 forever; the pinned
    // code is what makes each Play upload installable over the previous one.
    // Bump it together with the iOS bundleVersion (and this assertion).
    assert!(
        config.contains("\"versionCode\": 1027"),
        "tauri.conf.json must pin bundle > android > versionCode"
    );
}

#[test]
fn android_10_is_the_oldest_supported_release() {
    let config = read("tauri.conf.json");
    let gradle = read("gen/android/app/build.gradle.kts");

    // Below Android 10 the system WebView is too old for the keyboard insets
    // the terminal relies on: the keyboard covers the KeyBar and input line.
    // The Gradle value is the one that ships; the config copy is what a
    // regenerated Android project would start from, so the two must agree.
    assert!(
        gradle.contains("minSdk = 29"),
        "build.gradle.kts must set minSdk = 29 (Android 10)"
    );
    assert!(
        config.contains("\"minSdkVersion\": 29"),
        "tauri.conf.json must set bundle > android > minSdkVersion to 29"
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

// Release native-library hygiene: a stripped .so, Play debug symbols, a pinned
// NDK, and no build-machine paths. See packaging/ANDROID_BUILD_RUNBOOK.md,
// "Native library and NDK".

/// The text inside the braces that open after the first `header` in `source`.
fn braced_block<'a>(source: &'a str, header: &str) -> &'a str {
    let start = source
        .find(header)
        .unwrap_or_else(|| panic!("no `{header}` block"));
    let open = start
        + source[start..]
            .find('{')
            .unwrap_or_else(|| panic!("`{header}` opens no block"));
    let mut depth = 0;
    for (offset, ch) in source[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open + 1..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("`{header}` block is never closed");
}

#[test]
fn only_debug_builds_keep_native_debug_symbols() {
    let gradle = read("gen/android/app/build.gradle.kts");
    let debug_only = braced_block(&gradle, r#"onVariants(selector().withBuildType("debug"))"#);

    assert!(
        debug_only.contains("keepDebugSymbols"),
        "debug builds must keep native symbols through androidComponents.onVariants"
    );
    // BuildType has no `packaging`, so a packaging block inside
    // buildTypes { debug } binds to android.packaging and also keeps the symbol
    // tables in the release .so that ships on Play (about 10 MB more).
    assert_eq!(
        gradle.matches("keepDebugSymbols").count(),
        debug_only.matches("keepDebugSymbols").count(),
        "keepDebugSymbols outside the debug-only onVariants block applies to release too"
    );
}

#[test]
fn release_aab_carries_native_debug_symbols_for_play() {
    let gradle = read("gen/android/app/build.gradle.kts");
    let release = braced_block(&gradle, r#"getByName("release")"#);

    // Without them Play Console warns on upload and native crash reports show
    // bare addresses instead of function names.
    assert!(
        release.contains(r#"debugSymbolLevel = "SYMBOL_TABLE""#)
            || release.contains(r#"debugSymbolLevel = "FULL""#),
        "the release build type must set ndk.debugSymbolLevel"
    );
}

#[test]
fn gradle_pins_the_ndk_version() {
    let gradle = read("gen/android/app/build.gradle.kts");
    let android = braced_block(&gradle, "android {");
    let version = android
        .split("ndkVersion = \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("android.ndkVersion must be pinned: it picks the NDK that strips the .so");

    // AGP looks up a side-by-side NDK by its full Pkg.Revision. Pin a stable
    // release and point NDK_HOME (used for the Rust link) at the same folder.
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())),
        "ndkVersion must be a full revision such as 30.0.16248370, not {version:?}"
    );
}

#[test]
fn android_release_builds_remap_build_machine_paths() {
    // Panic locations and file!() otherwise ship C:\Users\<name>\.cargo\...
    // and the checkout path inside the .so. `tauri android build` compiles the
    // library in the CLI process, so the flags go into that process's env.
    let package = read("../package.json");
    assert!(
        package.contains(r#""tauri": "node scripts/tauri.mjs""#),
        "`pnpm tauri` must run through app/scripts/tauri.mjs"
    );
    let wrapper = read("../scripts/tauri.mjs");
    assert!(
        wrapper.contains("CARGO_ENCODED_RUSTFLAGS") && wrapper.contains("--remap-path-prefix="),
        "app/scripts/tauri.mjs must remap build-machine paths for Android release builds"
    );
    // CARGO_ENCODED_RUSTFLAGS replaces the CARGO_TARGET_<TRIPLE>_RUSTFLAGS that
    // the Tauri CLI sets, so its Android link flags must be carried over.
    for flag in [
        "-Clink-arg=-landroid",
        "-Clink-arg=-llog",
        "-Clink-arg=-lOpenSLES",
    ] {
        assert!(
            wrapper.contains(flag),
            "app/scripts/tauri.mjs must keep Tauri's link flag {flag}"
        );
    }

    // Gradle refuses a release library that still names this machine, e.g.
    // after a build that skipped the wrapper (`npx tauri`, `cargo tauri`).
    let task =
        read("gen/android/buildSrc/src/main/java/org/example/portty/kotlin/BuildTask.kt");
    let action = braced_block(&task, "fun assemble()");
    assert!(
        action.contains("assertNoBuildMachinePaths()"),
        "BuildTask must check release libraries for build-machine paths"
    );
}
