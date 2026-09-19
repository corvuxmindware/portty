# Mac CLI and iOS/TestFlight build runbook

This runbook installs Portty's desktop-side **command-line tools only** on a Mac
and publishes the mobile app to TestFlight. It does not build, install, or
publish a macOS desktop application.

Run every command from the repository root unless a step says otherwise.

The committed `org.example.portty` bundle identifier and `YOURTEAMID` Apple
team value are examples. Replace them with values you control in the Tauri
config, Xcode project, project.yml, and export/upload options before signing.
The APNs topic must match the signed app's bundle identifier.

## 1. What this workflow produces

The Mac installation contains exactly two executables:

| Source package | Installed command |
| --- | --- |
| `portty-cli` | `portty` |
| `portty-host` | `portty-host` |

The mobile build is an iPhone/iPad archive and IPA with bundle identifier
`org.example.portty`.

Do not run `tauri build`, `pnpm tauri build`, or create a macOS Xcode target.
Those are desktop-app workflows and are outside Portty's distribution model.
Use only the explicit `tauri ios build` command in this document.

## 2. Prerequisites

- macOS with Xcode and the Xcode Command Line Tools installed.
- Xcode signed into the Apple developer account for team `YOURTEAMID`.
- A valid Apple Development identity and App Store distribution access.
- Rust stable, Cargo, Node.js, Corepack, and pnpm.
- The Rust targets required by Tauri iOS.

Install or confirm the command-line prerequisites:

```sh
xcode-select -p
xcodebuild -version
rustup show
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
corepack enable
cd app
pnpm install --frozen-lockfile
cd ..
```

Confirm that Xcode can see signing identities:

```sh
security find-identity -v -p codesigning
```

Never commit certificates, private keys, App Store credentials, pairing
tickets, PINs, or peer data.

## 3. Record and validate the source

For a production upload, use a reviewed commit and begin with a clean working
tree. Do not delete or overwrite someone else's uncommitted changes.

```sh
git status --short
git rev-parse HEAD
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## 4. Build and install the Mac CLI only

Build only the two CLI packages:

```sh
cargo build --locked --release -p portty-cli -p portty-host
```

If the daemon is running, stop it before replacing its executable:

```sh
portty-host stop
```

It is safe to continue if that command reports that no daemon is running.

Install the two binaries into the current user's Cargo bin directory:

```sh
mkdir -p "$HOME/.cargo/bin"
install -m 0755 target/release/portty "$HOME/.cargo/bin/portty"
install -m 0755 target/release/portty-host "$HOME/.cargo/bin/portty-host"
```

Ensure `~/.cargo/bin` is on `PATH`, then verify the installation:

```sh
command -v portty
command -v portty-host
shasum -a 256 target/release/portty "$HOME/.cargo/bin/portty"
shasum -a 256 target/release/portty-host "$HOME/.cargo/bin/portty-host"
portty --help
portty --version
portty-host --help
portty-host --version
portty-host status
```

For each checksum command, the source and installed hashes must match. Both
help/version commands are side-effect-free smoke tests and must not start the
daemon.

Confirm that no desktop application was installed:

```sh
find /Applications "$HOME/Applications" -maxdepth 2 -type d -iname '*portty*.app' -print
```

Expected result: no output.

## 5. Choose the iOS version and build number

Apple requires each upload for a marketing version to use a new build number.
Portty currently uses dotted build numbers such as `1.3`; increment it for the
next upload, for example `1.4`.

Update the same build number in all four locations:

1. `app/src-tauri/tauri.conf.json` at `bundle.iOS.bundleVersion`.
2. `app/src-tauri/gen/apple/project.yml` at `CFBundleVersion`.
3. `app/src-tauri/gen/apple/portty-app_iOS/Info.plist` at
   `CFBundleVersion`.
4. `app/src-tauri/tests/ios_release_config.rs` in the build-number assertions.

If the public app version changes, update `version` in
`app/src-tauri/tauri.conf.json` and `CFBundleShortVersionString` in the generated
Apple project and Info.plist as part of the same reviewed change.

Do not pass a dotted value such as `1.4` to Tauri's `--build-number` option; that
option accepts an integer. This project stores the complete build number in its
configuration, so the build command below intentionally omits that option.

Verify the values before building:

```sh
rg -n 'bundleVersion|CFBundleVersion|CFBundleShortVersionString' \
  app/src-tauri/tauri.conf.json \
  app/src-tauri/gen/apple/project.yml \
  app/src-tauri/gen/apple/portty-app_iOS/Info.plist
```

## 6. Validate and build the iOS archive

Build the frontend first and run the mobile release checks:

```sh
cd app
pnpm exec tsc --noEmit
pnpm build
cargo test --manifest-path src-tauri/Cargo.toml
```

Create the signed App Store Connect archive. The configuration override skips
Tauri's `beforeBuildCommand` because the frontend was built explicitly in the
previous command:

```sh
pnpm tauri ios build --ci --export-method app-store-connect \
  --config '{"build":{"beforeBuildCommand":""}}'
cd ..
```

The main outputs are:

```text
app/src-tauri/gen/apple/build/portty-app_iOS.xcarchive
app/src-tauri/gen/apple/build/arm64/Portty.ipa
```

## 7. Inspect the archive before uploading

Confirm the version, build number, architecture, platform, and signing team:

```sh
plutil -p \
  app/src-tauri/gen/apple/build/portty-app_iOS.xcarchive/Info.plist
plutil -p \
  app/src-tauri/gen/apple/build/portty-app_iOS.xcarchive/Products/Applications/Portty.app/Info.plist
```

Required results:

- `CFBundleIdentifier` is `org.example.portty`.
- `CFBundleVersion` is the new build number.
- `Architectures` contains `arm64`.
- `CFBundleSupportedPlatforms` contains only `iPhoneOS`.
- `DTPlatformName` is `iphoneos`.
- The team is `YOURTEAMID`.

Inspect the actual IPA, not the temporary `build/Payload` directory:

```sh
unzip -l app/src-tauri/gen/apple/build/arm64/Portty.ipa
if unzip -l app/src-tauri/gen/apple/build/arm64/Portty.ipa | grep -q libapp.a; then
  echo "ERROR: libapp.a was bundled in the IPA"
  exit 1
else
  echo "OK: libapp.a is not bundled"
fi
```

The first command should show one `Payload/Portty.app`. The second check must
print `OK`: `libapp.a` is linked into the executable and must not be copied into
the application bundle.

Stop if the IPA contains a macOS app, a desktop executable, `libapp.a`, source
files, credentials, identity data, pairing data, or build caches.

## 8. Upload to TestFlight

The tracked upload configuration uses automatic App Store Connect signing for
the Portty team and tells Xcode to upload rather than only export.

```sh
xcodebuild -exportArchive \
  -archivePath app/src-tauri/gen/apple/build/portty-app_iOS.xcarchive \
  -exportPath app/src-tauri/gen/apple/build/upload \
  -exportOptionsPlist app/src-tauri/gen/apple/UploadOptions.plist \
  -allowProvisioningUpdates
```

Wait for both messages:

```text
Upload succeeded.
** EXPORT SUCCEEDED **
```

Then confirm Xcode recorded the uploaded build number and a successful upload:

```sh
plutil -p app/src-tauri/gen/apple/build/portty-app_iOS.xcarchive/Info.plist
```

Under `Distributions`, the expected values are `destination = upload`,
`uploadedBuildNumber = <new build number>`, and `uploadEvent.state = success`.

The build can remain in Apple's **Processing** state for a while after the
upload succeeds. When processing finishes, open App Store Connect, review any
compliance prompt, add the build to the intended TestFlight tester group, and
perform the phone smoke test.

## 9. Final checklist

- [ ] Installed hashes match `target/release/portty` and `portty-host`.
- [ ] No Portty macOS `.app` exists in `/Applications` or `~/Applications`.
- [ ] Workspace, frontend, and iOS release tests passed.
- [ ] Marketing version and build number are correct.
- [ ] Archive platform is `iPhoneOS` and architecture is `arm64`.
- [ ] IPA contains no `libapp.a` or desktop application.
- [ ] Xcode reports `Upload succeeded` and `EXPORT SUCCEEDED`.
- [ ] App Store Connect finishes processing the new build.
- [ ] The TestFlight build is assigned and smoke-tested on a physical phone.
