/**
 * App-owned line icons - canonical Lucide geometry (https://lucide.dev, ISC),
 * inlined as SVG. They stay inline SVG (not an icon font) on purpose: Android
 * WebView font fallback varies by OEM and would render a missing symbol font as
 * a boxed X, whereas these paths render identically everywhere. Generated from
 * lucide-static so the whole set is consistent - do not hand-edit path data;
 * add a name to the map and regenerate instead.
 */
export type IconName =
  | "arrow-left"
  | "arrow-up"
  | "arrow-down"
  | "arrow-right"
  | "chevron-up"
  | "chevron-down"
  | "download"
  | "upload"
  | "play"
  | "pause"
  | "keyboard"
  | "power"
  | "warning"
  | "lock"
  | "unlock"
  | "disconnect"
  | "host"
  | "switch"
  | "edit"
  | "check"
  | "close"
  | "monitor"
  | "qr-code"
  | "flashlight"
  | "send"
  | "stop"
  | "link"
  | "terminal"
  | "search"
  | "think"
  | "external-link"
  | "more"
  | "settings"
  | "scroll-bottom"
  | "bot"
  | "circle"
  | "dot"
  | "star"
  | "trash";

const ICON_SVG: Record<IconName, string> = {
  "arrow-left": "<path d=\"m12 19-7-7 7-7\" /><path d=\"M19 12H5\" />",
  "arrow-up": "<path d=\"m5 12 7-7 7 7\" /><path d=\"M12 19V5\" />",
  "arrow-down": "<path d=\"M12 5v14\" /><path d=\"m19 12-7 7-7-7\" />",
  "arrow-right": "<path d=\"M5 12h14\" /><path d=\"m12 5 7 7-7 7\" />",
  "chevron-up": "<path d=\"m18 15-6-6-6 6\" />",
  "chevron-down": "<path d=\"m6 9 6 6 6-6\" />",
  "download": "<path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\" /><polyline points=\"7 10 12 15 17 10\" /><line x1=\"12\" x2=\"12\" y1=\"15\" y2=\"3\" />",
  "upload": "<path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\" /><polyline points=\"17 8 12 3 7 8\" /><line x1=\"12\" x2=\"12\" y1=\"3\" y2=\"15\" />",
  "play": "<polygon points=\"6 3 20 12 6 21 6 3\" />",
  "pause": "<rect x=\"14\" y=\"4\" width=\"4\" height=\"16\" rx=\"1\" /><rect x=\"6\" y=\"4\" width=\"4\" height=\"16\" rx=\"1\" />",
  "keyboard": "<path d=\"M10 8h.01\" /><path d=\"M12 12h.01\" /><path d=\"M14 8h.01\" /><path d=\"M16 12h.01\" /><path d=\"M18 8h.01\" /><path d=\"M6 8h.01\" /><path d=\"M7 16h10\" /><path d=\"M8 12h.01\" /><rect width=\"20\" height=\"16\" x=\"2\" y=\"4\" rx=\"2\" />",
  "power": "<path d=\"M12 2v10\" /><path d=\"M18.4 6.6a9 9 0 1 1-12.77.04\" />",
  "warning": "<path d=\"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3\" /><path d=\"M12 9v4\" /><path d=\"M12 17h.01\" />",
  "lock": "<rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\" /><path d=\"M7 11V7a5 5 0 0 1 10 0v4\" />",
  "unlock": "<rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\" /><path d=\"M7 11V7a5 5 0 0 1 9.9-1\" />",
  "disconnect": "<path d=\"m19 5 3-3\" /><path d=\"m2 22 3-3\" /><path d=\"M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z\" /><path d=\"M7.5 13.5 10 11\" /><path d=\"M10.5 16.5 13 14\" /><path d=\"m12 6 6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4l-2.6-2.6a2.4 2.4 0 0 0-3.4 0Z\" />",
  "host": "<rect width=\"20\" height=\"8\" x=\"2\" y=\"2\" rx=\"2\" ry=\"2\" /><rect width=\"20\" height=\"8\" x=\"2\" y=\"14\" rx=\"2\" ry=\"2\" /><line x1=\"6\" x2=\"6.01\" y1=\"6\" y2=\"6\" /><line x1=\"6\" x2=\"6.01\" y1=\"18\" y2=\"18\" />",
  "switch": "<path d=\"M8 3 4 7l4 4\" /><path d=\"M4 7h16\" /><path d=\"m16 21 4-4-4-4\" /><path d=\"M20 17H4\" />",
  "edit": "<path d=\"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z\" /><path d=\"m15 5 4 4\" />",
  "check": "<path d=\"M20 6 9 17l-5-5\" />",
  "close": "<path d=\"M18 6 6 18\" /><path d=\"m6 6 12 12\" />",
  "monitor": "<rect width=\"20\" height=\"14\" x=\"2\" y=\"3\" rx=\"2\" /><line x1=\"8\" x2=\"16\" y1=\"21\" y2=\"21\" /><line x1=\"12\" x2=\"12\" y1=\"17\" y2=\"21\" />",
  "qr-code": "<rect width=\"5\" height=\"5\" x=\"3\" y=\"3\" rx=\"1\" /><rect width=\"5\" height=\"5\" x=\"16\" y=\"3\" rx=\"1\" /><rect width=\"5\" height=\"5\" x=\"3\" y=\"16\" rx=\"1\" /><path d=\"M21 16h-3a2 2 0 0 0-2 2v3\" /><path d=\"M21 21v.01\" /><path d=\"M12 7v3a2 2 0 0 1-2 2H7\" /><path d=\"M3 12h.01\" /><path d=\"M12 3h.01\" /><path d=\"M12 16v.01\" /><path d=\"M16 12h1\" /><path d=\"M21 12v.01\" /><path d=\"M12 21v-1\" />",
  "flashlight": "<path d=\"M18 6c0 2-2 2-2 4v10a2 2 0 0 1-2 2h-4a2 2 0 0 1-2-2V10c0-2-2-2-2-4V2h12z\" /><line x1=\"6\" x2=\"18\" y1=\"6\" y2=\"6\" /><line x1=\"12\" x2=\"12\" y1=\"12\" y2=\"12\" />",
  "send": "<path d=\"M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z\" /><path d=\"m21.854 2.147-10.94 10.939\" />",
  "stop": "<rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\" />",
  "link": "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\" /><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\" />",
  "terminal": "<path d=\"m7 11 2-2-2-2\" /><path d=\"M11 13h4\" /><rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\" ry=\"2\" />",
  "search": "<circle cx=\"11\" cy=\"11\" r=\"8\" /><path d=\"m21 21-4.3-4.3\" />",
  "think": "<path d=\"M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5\" /><path d=\"M9 18h6\" /><path d=\"M10 22h4\" />",
  "external-link": "<path d=\"M15 3h6v6\" /><path d=\"M10 14 21 3\" /><path d=\"M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6\" />",
  "more": "<circle cx=\"12\" cy=\"12\" r=\"1\" /><circle cx=\"19\" cy=\"12\" r=\"1\" /><circle cx=\"5\" cy=\"12\" r=\"1\" />",
  "settings": "<path d=\"M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z\" /><circle cx=\"12\" cy=\"12\" r=\"3\" />",
  "scroll-bottom": "<path d=\"M12 17V3\" /><path d=\"m6 11 6 6 6-6\" /><path d=\"M19 21H5\" />",
  "bot": "<path d=\"M12 8V4H8\" /><rect width=\"16\" height=\"12\" x=\"4\" y=\"8\" rx=\"2\" /><path d=\"M2 14h2\" /><path d=\"M20 14h2\" /><path d=\"M15 13v2\" /><path d=\"M9 13v2\" />",
  "circle": "<circle cx=\"12\" cy=\"12\" r=\"7\" />",
  "dot": "<circle cx=\"12\" cy=\"12\" r=\"5\" fill=\"currentColor\" stroke=\"none\" />",
  /* A `path`, like every other glyph here - `polygon` would have been the only
     one of its kind in this record, and these are injected as an SVG innerHTML
     fragment, so staying with the element type the rest already proves is worth
     more than the shorter markup.

     Stroke-only: the FILLED state is CSS (`fill: currentColor`), so one glyph
     serves both "this is the default" and "make it the default". */
  "star":
    "<path d=\"M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.123 2.123 0 0 0-1.973 0L6.396 21.11a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.895a.53.53 0 0 1 .294-.904l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z\" />",
  "trash": "<path d=\"M3 6h18\" /><path d=\"M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2\" /><path d=\"M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6\" /><path d=\"M10 11v6\" /><path d=\"M14 11v6\" />",
};

export function Icon(props: { name: IconName; class?: string }) {
  return (
    <svg
      class={`portty-icon${props.class ? ` ${props.class}` : ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      innerHTML={ICON_SVG[props.name]}
    />
  );
}
