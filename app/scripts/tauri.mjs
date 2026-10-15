// `pnpm tauri ...` runs the Tauri CLI through this file. For an Android
// RELEASE build it first adds --remap-path-prefix flags, so the shipped
// libportty_app_lib.so names no build-machine folders. Panic locations,
// file!() and tracing metadata keep every source path; without this the
// library carries C:\Users\<name>\.cargo\registry\... and the checkout path.
// Cargo's trim-paths would do this, but it is not stable yet.
//
// The flags must live in THIS process: `tauri android build` compiles the
// library itself, then Gradle's rustBuild task runs cargo again with this
// process's CARGO_* variables, so both passes agree (the second is a no-op).
// gen/android/buildSrc/.../BuildTask.kt fails a release build that still
// leaks a path, e.g. one started with `npx tauri` or `cargo tauri`.
import { realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const android = args.indexOf("android");
const androidRelease =
  android >= 0 &&
  args[android + 1] === "build" &&
  !args.includes("--debug") &&
  !args.includes("-d");

if (androidRelease) {
  process.env.CARGO_ENCODED_RUSTFLAGS = releaseRustflags();
}

createRequire(import.meta.url)("@tauri-apps/cli/tauri.js");

// Cargo takes ONE source of rustflags: CARGO_ENCODED_RUSTFLAGS, else
// RUSTFLAGS, else the CARGO_TARGET_<TRIPLE>_RUSTFLAGS that the Tauri CLI sets.
// Setting the first replaces the others, so carry over whichever would have
// applied - the caller's own flags, else Tauri's Android link flags
// (cargo-mobile2 src/android/target.rs) - and append the remaps.
function releaseRustflags() {
  const encoded = process.env.CARGO_ENCODED_RUSTFLAGS;
  const plain = process.env.RUSTFLAGS?.trim();
  const inherited = encoded
    ? encoded.split("\x1f")
    : plain
      ? plain.split(/\s+/)
      : ["-Clink-arg=-landroid", "-Clink-arg=-llog", "-Clink-arg=-lOpenSLES"];
  if (inherited.some((flag) => flag.startsWith("--remap-path-prefix="))) {
    return inherited.join("\x1f");
  }

  const home = homedir();
  // rustc applies the LAST prefix that matches, so general before specific.
  const folders = [
    [home, "~"],
    [process.env.CARGO_HOME || path.join(home, ".cargo"), "/cargo"],
    [fileURLToPath(new URL("../..", import.meta.url)), "/portty"],
    [process.env.CARGO_TARGET_DIR, "/target"],
  ];
  const remaps = folders.flatMap(([folder, to]) =>
    folder ? spellings(folder).map((from) => `--remap-path-prefix=${from}=${to}`) : [],
  );
  return [...inherited, ...remaps].join("\x1f");
}

// Matching is case-sensitive: cover the spelling cargo is given and the one
// on disk.
function spellings(folder) {
  const given = path.resolve(folder);
  let onDisk = given;
  try {
    onDisk = realpathSync.native(given);
  } catch {
    // Not created yet, so only the given spelling can occur.
  }
  return [...new Set([given, onDisk])];
}
