//! Guard the committed iOS settings used for distribution builds.

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

fn config_string(name: &str) -> String {
    let prefix = format!("\"{name}\": \"");
    read("tauri.conf.json")
        .lines()
        .find_map(|line| line.trim().strip_prefix(&prefix))
        .and_then(|value| value.split('"').next())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| panic!("tauri.conf.json is missing {name}"))
        .to_owned()
}

#[test]
fn privacy_manifest_covers_framework_required_reason_apis() {
    let manifest = read("gen/apple/portty-app_iOS/PrivacyInfo.xcprivacy");

    for required in [
        "NSPrivacyTracking",
        "NSPrivacyCollectedDataTypes",
        "NSPrivacyAccessedAPICategoryFileTimestamp",
        "C617.1",
        "NSPrivacyAccessedAPICategoryUserDefaults",
        "CA92.1",
    ] {
        assert!(
            manifest.contains(required),
            "privacy manifest is missing {required}"
        );
    }
}

#[test]
fn push_entitlement_is_production_for_release_and_development_for_debug() {
    // The single most important push-distribution setting. If release ships with
    // aps-environment=development, every TestFlight/App Store build registers a
    // sandbox APNs token and the relay's POST to api.push.apple.com returns
    // BadDeviceToken - the tap-to-approve doorbell silently never fires. This
    // guards the committed config; the actual archive still has to be built in
    // Xcode, but a regression of these files fails CI first.
    let release = read("gen/apple/portty-app_iOS/portty-app_iOS.release.entitlements");
    assert!(
        release.contains("<key>aps-environment</key>")
            && release.contains("<string>production</string>"),
        "release entitlements must declare aps-environment=production"
    );
    assert!(
        !release.contains("<string>development</string>"),
        "release entitlements must NOT use the development APNs environment"
    );

    let debug = read("gen/apple/portty-app_iOS/portty-app_iOS.entitlements");
    assert!(
        debug.contains("<key>aps-environment</key>")
            && debug.contains("<string>development</string>"),
        "debug entitlements should keep aps-environment=development"
    );

    // And the release build configuration must actually be wired to the
    // production entitlements file, not just have the file sitting unused.
    let project = read("gen/apple/project.yml");
    assert!(
        project.contains("CODE_SIGN_ENTITLEMENTS: portty-app_iOS/portty-app_iOS.release.entitlements"),
        "project.yml release config must point CODE_SIGN_ENTITLEMENTS at the production entitlements"
    );
}

/// The build number and marketing version live in FOUR places, and Apple
/// rejects an archive whose copies disagree. Pinning them in one test is what
/// turns a partial bump into a failing build instead of a wasted upload.
///
/// They have already drifted once: `project.yml` sat at `0.1.0`/`1.16` while
/// `tauri.conf.json` and `Info.plist` were at `0.1.2`/`1.17`, and these
/// assertions still named `1.14`. Two of the three were invisible because
/// `cargo test` stops at the first failing test BINARY, so this file never ran.
/// Bump every constant below together - see packaging/MAC_IOS_BUILD_RUNBOOK.md
/// section 5.
const MARKETING_VERSION: &str = "0.1.3";
const BUILD_NUMBER: &str = "1.30";

#[test]
fn info_plist_has_mobile_permission_descriptions_and_build_number() {
    let info = read("gen/apple/portty-app_iOS/Info.plist");

    for required in [
        "NSCameraUsageDescription".to_string(),
        "NSFaceIDUsageDescription".to_string(),
        "<key>CFBundleVersion</key>".to_string(),
        format!("<string>{BUILD_NUMBER}</string>"),
        format!("<string>{MARKETING_VERSION}</string>"),
    ] {
        assert!(info.contains(&required), "Info.plist is missing {required}");
    }
}

/// The copy that actually reached the built app used to be checked on its own,
/// which is precisely how `project.yml` drifted two versions behind unnoticed.
#[test]
fn every_copy_of_the_ios_version_agrees() {
    let project = read("gen/apple/project.yml");
    let config = read("tauri.conf.json");
    let info = read("gen/apple/portty-app_iOS/Info.plist");

    for (label, haystack, needle) in [
        (
            "project.yml CFBundleVersion",
            &project,
            format!("CFBundleVersion: \"{BUILD_NUMBER}\""),
        ),
        (
            "project.yml CFBundleShortVersionString",
            &project,
            format!("CFBundleShortVersionString: {MARKETING_VERSION}"),
        ),
        (
            "tauri.conf.json bundleVersion",
            &config,
            format!("\"bundleVersion\": \"{BUILD_NUMBER}\""),
        ),
        (
            "tauri.conf.json version",
            &config,
            format!("\"version\": \"{MARKETING_VERSION}\""),
        ),
        (
            "Info.plist CFBundleVersion",
            &info,
            format!("<string>{BUILD_NUMBER}</string>"),
        ),
    ] {
        assert!(
            haystack.contains(&needle),
            "{label} disagrees: expected {needle}. All four locations must be \
             bumped together (MAC_IOS_BUILD_RUNBOOK.md section 5)."
        );
    }
}

#[test]
fn export_targets_app_store_connect_with_automatic_signing() {
    let export = read("gen/apple/ExportOptions.plist");
    let team = config_string("developmentTeam");

    for required in [
        "app-store-connect",
        team.as_str(),
        "automatic",
        "uploadSymbols",
    ] {
        assert!(
            export.contains(required),
            "ExportOptions.plist is missing {required}"
        );
    }
    assert!(!export.contains("<string>debugging</string>"));
}

#[test]
fn upload_targets_app_store_connect_instead_of_a_local_export() {
    let upload = read("gen/apple/UploadOptions.plist");
    let team = config_string("developmentTeam");

    for required in [
        "app-store-connect",
        team.as_str(),
        "automatic",
        "uploadSymbols",
        "<string>upload</string>",
    ] {
        assert!(
            upload.contains(required),
            "UploadOptions.plist is missing {required}"
        );
    }
    assert!(!upload.contains("<string>debugging</string>"));
}

#[test]
fn rust_static_library_is_linked_but_never_bundled_as_a_resource() {
    let project = read("gen/apple/portty-app.xcodeproj/project.pbxproj");
    assert!(project.contains("libapp.a in Frameworks"));
    assert!(
        !project.contains("libapp.a in Resources"),
        "App Store rejects a loose libapp.a inside the application bundle"
    );
}

/// Apple refuses any upload below iOS 15.0 from Spring 2027, and build 1.19 came
/// back with warning 90068 for declaring 14.0. Nothing in the tree spells
/// `MinimumOSVersion` out: it is derived from `IPHONEOS_DEPLOYMENT_TARGET`, which
/// xcodegen writes into the pbxproj from `project.yml`. Both copies are
/// committed, so both can drift - the same way `project.yml` fell two versions
/// behind on the build number - and the drift is invisible until an upload comes
/// back warned or rejected.
#[test]
fn ios_deployment_target_meets_the_app_store_floor() {
    const MIN_IOS: &str = "15.0";

    let project = read("gen/apple/project.yml");
    assert!(
        project.contains(&format!("iOS: {MIN_IOS}")),
        "project.yml must declare deploymentTarget iOS: {MIN_IOS} - it is the \
         xcodegen source for IPHONEOS_DEPLOYMENT_TARGET"
    );

    // Every configuration, not just one: a debug-only bump still ships a release
    // archive Apple warns about.
    let pbxproj = read("gen/apple/portty-app.xcodeproj/project.pbxproj");
    let targets: Vec<&str> = pbxproj
        .lines()
        .filter(|line| line.contains("IPHONEOS_DEPLOYMENT_TARGET"))
        .collect();
    assert!(
        !targets.is_empty(),
        "the pbxproj must pin IPHONEOS_DEPLOYMENT_TARGET"
    );
    for line in targets {
        assert!(
            line.contains(&format!("IPHONEOS_DEPLOYMENT_TARGET = {MIN_IOS};")),
            "every build configuration must target iOS {MIN_IOS}, found: {}",
            line.trim()
        );
    }
}

/// Portty's layout is designed and tested for a phone only. xcodegen defaults an
/// iOS target to iPhone AND iPad ("1,2"), which would offer the app to iPad users
/// and make App Store Connect demand iPad screenshots. `project.yml` is the
/// source and the pbxproj is the committed copy, so both are checked.
#[test]
fn ios_app_targets_iphone_only() {
    let project = read("gen/apple/project.yml");
    assert!(
        project.contains("TARGETED_DEVICE_FAMILY: \"1\""),
        "project.yml must set TARGETED_DEVICE_FAMILY: \"1\" (iPhone only)"
    );

    let pbxproj = read("gen/apple/portty-app.xcodeproj/project.pbxproj");
    let families: Vec<&str> = pbxproj
        .lines()
        .filter(|line| line.contains("TARGETED_DEVICE_FAMILY"))
        .collect();
    assert!(
        !families.is_empty(),
        "the pbxproj must pin TARGETED_DEVICE_FAMILY"
    );
    for line in families {
        let value = line
            .split('=')
            .nth(1)
            .unwrap_or_default()
            .trim()
            .trim_end_matches(';')
            .trim_matches('"');
        assert_eq!(
            value,
            "1",
            "every build configuration must target iPhone only, found: {}",
            line.trim()
        );
    }
}

/// Export compliance. Portty bundles its own standard encryption and declares
/// `ITSAppUsesNonExemptEncryption` as false (see the comment in `project.yml`).
/// `true` would make App Store Connect reject the upload (error 90592) until an
/// approved export document and its code are attached, so a change in either
/// direction must be a decision, not an accident. Both copies must agree.
#[test]
fn export_compliance_is_declared_exempt_in_both_copies() {
    let project = read("gen/apple/project.yml");
    assert!(
        project.contains("ITSAppUsesNonExemptEncryption: false"),
        "project.yml must declare ITSAppUsesNonExemptEncryption: false"
    );

    let plist = read("gen/apple/portty-app_iOS/Info.plist");
    let key = plist
        .find("<key>ITSAppUsesNonExemptEncryption</key>")
        .expect("Info.plist must declare ITSAppUsesNonExemptEncryption");
    let after_key = plist[key..]
        .split("<key>")
        .nth(1)
        .and_then(|rest| rest.split("</key>").nth(1))
        .unwrap_or_default();
    assert!(
        after_key.trim_start().starts_with("<false/>"),
        "Info.plist must set ITSAppUsesNonExemptEncryption to <false/>"
    );
}

#[test]
fn tauri_config_agrees_with_the_ios_project_on_identifier_and_team() {
    let config = read("tauri.conf.json");
    assert!(config.contains(&format!("\"bundleVersion\": \"{BUILD_NUMBER}\"")));
    let identifier = config_string("identifier");
    let team = config_string("developmentTeam");
    assert!(
        identifier.contains('.'),
        "app identifier must be reverse DNS style"
    );
    assert_eq!(team.len(), 10, "Apple team ID must be 10 characters");

    let project = read("gen/apple/project.yml");
    assert!(project.contains(&format!("PRODUCT_BUNDLE_IDENTIFIER: {identifier}")));
    assert!(project.contains(&format!("DEVELOPMENT_TEAM: {team}")));

    let xcode_project = read("gen/apple/portty-app.xcodeproj/project.pbxproj");
    assert!(xcode_project.contains(&format!("PRODUCT_BUNDLE_IDENTIFIER = {identifier};")));
    assert!(xcode_project.contains(&format!("DEVELOPMENT_TEAM = \"{team}\";")));
}
