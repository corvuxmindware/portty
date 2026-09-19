import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import tailwindcss from "@tailwindcss/vite";

// Tauri dev server convention: fixed port so the Rust side's devUrl matches.
export default defineConfig({
  plugins: [solid(), tailwindcss()],
  clearScreen: false,
  // Loopback by DEFAULT. This server has no authentication and serves the whole
  // app bundle, so `host: true` (0.0.0.0) exposed every dev session to the
  // network Portty happened to be on - a coffee-shop or office LAN included -
  // for as long as `pnpm dev` ran.
  //
  // Mobile dev still needs LAN reachability, so name the interface explicitly,
  // which also documents the exposure at the call site:
  //   TAURI_DEV_HOST=$(ipconfig getifaddr en0) pnpm tauri ios dev
  //
  // It must be that env var and not `tauri ios dev --host`: the flag is consumed
  // by the TAURI CLI (it only rewrites the devUrl the phone loads) and never
  // reaches Vite, which then still binds to loopback and the phone times out
  // waiting for a server that was never exposed. TAURI_DEV_HOST is the one knob
  // both sides read.
  server: { host: process.env.TAURI_DEV_HOST ?? "127.0.0.1", port: 1420, strictPort: true },
  build: { target: "esnext" },
});
