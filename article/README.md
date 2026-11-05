# Research article

`ebpf-edr-flagship-short.pdf` is the 11-page paper "An eBPF Endpoint Detection Engine: Ten Behavioral Detectors, Measured Results, and Failures". `ebpf-edr-flagship-short.md` is its source.

## Build the PDF

Prerequisites: pandoc 3.x, XeLaTeX (TeX Live with `xetex`, `titlesec`, `needspace`, `caption`, `float`, `colortbl`), Python 3, and the fonts below.

1. Install Liberation Sans (`fonts-liberation` or `fonts-liberation2`).
2. Download Roboto Mono Regular and Italic (TrueType) and save them as `fonts/RobotoMono-Regular.ttf` and `fonts/RobotoMono-Italic.ttf`. Details are in `fonts/README.md`. No font files are bundled here.
3. From this folder run `python3 latex/build.py ebpf-edr-flagship-short.md`. The PDF is written to `build/ebpf-edr-flagship-short.pdf`.

To regenerate the figures (needs matplotlib and Liberation Sans) run `python3 latex/make_figures.py`.
