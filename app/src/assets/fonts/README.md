# Bundled terminal font

`JetBrainsMonoNerdFontMono-Regular.ttf` and `-Bold.ttf` are the **Mono** (fixed
single-width) variant of **JetBrains Mono Nerd Font**.

Why it is bundled: Android's WebView does not ship `SF Mono`/`JetBrains Mono`,
and its default `monospace` lacks box-drawing, powerline, and Nerd-Font glyphs,
so terminal symbols rendered as tofu there. Shipping the font makes iOS and
Android render terminal output identically. Loaded via `@font-face` in
`src/styles.css` and used first in the xterm `fontFamily` (see `src/App.tsx`).

## Licenses

- **JetBrains Mono and the patched font** - SIL Open Font License, Version 1.1.
  The upstream JetBrains license and copyright are in [OFL.txt](OFL.txt).
- **Nerd Fonts** provides the patched font, glyphs, and patcher. Its upstream
  [license](NERD-FONTS-LICENSE.txt) distinguishes the OFL-licensed patched fonts
  from MIT-licensed original source code. The upstream
  [JetBrains Mono attribution](NERD-FONTS-ATTRIBUTION.md) lists included glyph
  sources and their licenses.

These files accompany the bundled fonts in the source distribution. Include the
applicable full license and attribution texts with redistributed mobile apps.
