import { defineConfig } from "vitest/config";

// Deliberately NOT the app's vite.config.ts: the unit tests cover pure logic
// modules (lib/echo, lib/policy, lib/altscreen) that need no DOM, no Solid
// transform, and no Tauri - plain node keeps them dependency-free and fast.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
