/* @refresh reload */
import { render } from "solid-js/web";
import App from "./App";
import { BiometricGate } from "./BiometricGate";

// Eagerly load the bundled terminal font at startup. Web fonts load lazily (only
// when first used), so the terminal's FIRST frame used to draw before the font
// arrived and Android substituted its plain monospace - broken box-drawing, no
// powerline/Nerd glyphs. Kicking the load off here makes the font ready well
// before any terminal renders. (The terminal also re-measures on fonts.ready;
// see App.tsx ensureTerm.)
if (typeof document !== "undefined" && document.fonts) {
  for (const spec of [
    '400 16px "JetBrainsMono Nerd Font Mono"',
    '700 16px "JetBrainsMono Nerd Font Mono"',
  ]) {
    document.fonts.load(spec).catch(() => {});
  }
}

const root = document.getElementById("root");
if (!root) throw new Error("#root not found");
// BiometricGate wraps the whole app: on cold start it gates App's first mount
// behind a successful unlock; on background resume it re-locks via an overlay.
// Passes through silently on desktop / devices without biometric.
render(
  () => (
    <BiometricGate>
      <App />
    </BiometricGate>
  ),
  root,
);
