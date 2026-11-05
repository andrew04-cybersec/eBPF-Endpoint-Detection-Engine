# Fonts (not redistributed here)

The PDF uses two fonts that this package does not ship.

- Liberation Sans (stands in for Arial). Install the system package `fonts-liberation2` or `fonts-liberation`. License: SIL Open Font License 1.1.
- Roboto Mono Regular and Italic, for code. Download from Google Fonts or the `@fontsource/roboto-mono` npm package (SIL Open Font License 1.1) and save the two TrueType files in this folder as `RobotoMono-Regular.ttf` and `RobotoMono-Italic.ttf`.
  The fontsource files are WOFF subsets, so convert or download the TTF from Google Fonts instead.

The Open Font License permits bundling unmodified fonts with their license text, but redistribution was not confirmed for this package, so the files are left out. If Roboto Mono is missing, `python3 latex/build.py --fallback-mono` builds with Liberation Mono instead, and the appearance of code text will differ from the reference paper.
