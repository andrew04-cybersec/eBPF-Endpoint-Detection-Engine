#!/usr/bin/env python3
"""Build the article PDF from the Markdown source.
Run from the article/ folder:  python3 latex/build.py ebpf-edr-flagship-short.md
Needs pandoc 3.x, xelatex, Liberation Sans and the Roboto Mono TTFs (see fonts/README.md).
Output: build/ebpf-edr-flagship-short.pdf"""
import re, subprocess, sys, os, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
SRC = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else 'ebpf-edr-flagship-short.md'
OUT = os.path.splitext(os.path.basename(SRC))[0]
B = 'build'
os.makedirs(B, exist_ok=True)
md = open(SRC, encoding='utf-8').read()

def pandoc(text, extra=()):
    r = subprocess.run(['pandoc', '-f', 'markdown+smart', '-t', 'latex', '--no-highlight', '--wrap=none', *extra],
                       input=text, capture_output=True, text=True)
    if r.returncode: sys.exit(r.stderr)
    return r.stdout

title = re.match(r'# (.+)', md).group(1).strip()
head, rest = md.split('\n## 1. Abstract', 1)
abstract_md, body_md = rest.split('\n## 2. ', 1)
body_md = '## 2. ' + body_md
abstract_md = abstract_md.replace('\n---', '').strip()
meta = {}
for ln in head.splitlines():
    m = re.match(r'\*\*(.+?):\*\* (.+)', ln)
    if m: meta[m.group(1)] = m.group(2)
author, _, rest_a = meta['Author'].partition(', ')
field, _, date = rest_a.rpartition(', ')
meta_md = '\n\n'.join('%s: %s' % (k, v) for k, v in [
    ('Repository', '<' + meta['Project'].split('https://')[1].join(['https://', '']) + '>' if False else '<https://' + meta['Project'].split('https://')[1] + '>'),
    ('Code state described', meta['Code state described'])])

# body preparation
body_md = re.sub(r'\n---\n', '\n', body_md)
body_md = body_md.replace('\n## Appendix A', '\n```{=latex}\n\\clearpage\n```\n\n## Appendix A')
# references block as bracketed labels in a small font
m = re.search(r'(\n)(1\. Repository: .*?)(\n\n\n|\Z)', body_md, re.S)
blk_start = body_md.index('\n1. Repository:')
blk_end = body_md.index('\n```{=latex}\n\\clearpage') if '\\clearpage' in body_md else len(body_md)
block = body_md[blk_start:blk_end]
block = re.sub(r'(?m)^(\d+)\. ', lambda mo: '**[%s]** ' % mo.group(1), block)
block = re.sub(r'(?m)^(\*\*\[\d+\]\*\* .*)$', lambda mo: mo.group(1) + '\n', block)
body_md = body_md[:blk_start] + '\n::: {.refs}\n' + block.strip('\n') + '\n:::\n' + body_md[blk_end:]

fm = ['--lua-filter=latex/filter.lua']
body = pandoc(body_md, ['--shift-heading-level-by=-1', *fm])
abstract = pandoc(abstract_md)
meta_tex = pandoc(meta_md)

# table post-processing: grid borders, header fill, no minipages
def style_tables(t):
    def one(mo):
        tb = mo.group(0)
        spec = re.match(r'\\begin\{longtable\}\[\]\{(.*?)\}\n\\toprule', tb, re.S).group(1)
        n = spec.count('p{')
        new_spec = '|' + ''.join(re.findall(r'>\{[^}]*\}p\{[^\n]*?\}(?=\n|@)', spec) and [] or [])
        cols = re.findall(r'(>\{\\raggedright\\arraybackslash\}p\{[^\n]*?\\real\{[0-9.]+\}\})', spec)
        spec2 = '|' + '|'.join(cols) + '|'
        tb = tb.replace(spec, spec2, 1)
        tb = re.sub(r'\\columnwidth - (\d+)\\tabcolsep', lambda mo: '\\columnwidth - %d\\tabcolsep - %d\\arrayrulewidth' % (int(mo.group(1)) + 2, n + 1), tb)
        tb = re.sub(r'\\toprule\\noalign\{\}\n', '\\\\hline\\\\rowcolor{tblhead}\n', tb)
        tb = re.sub(r'\\midrule\\noalign\{\}\n', '\\\\hline\n', tb)
        tb = re.sub(r'\\bottomrule\\noalign\{\}\n', '', tb)
        tb = re.sub(r'\\begin\{minipage\}\[b\]\{\\linewidth\}\\raggedright\n', '', tb)
        tb = re.sub(r'\n\\end\{minipage\}', '', tb)
        tb = re.sub(r'\\\\\n(?!\\hline|\\endhead|\\endfirsthead|\\endlastfoot|\\end\{longtable\})', '\\\\\\\\ \\\\hline\n', tb)
        # make header cells bold
        def bold_head(hm):
            h = hm.group(0)
            cells = h.split(' & ')
            cells = [('\\textbf{' + c.strip() + '}') if not c.strip().startswith('\\textbf') else c for c in cells]
            return ' & '.join(cells)
        tb = re.sub(r'(?<=rowcolor\{tblhead\}\n)(.*?)(?= \\\\\n)', bold_head, tb, flags=re.S)
        tb = tb.replace('\\end{longtable}', '\\hline\n\\end{longtable}')
        size = '\\fontsize{8}{10}\\selectfont' if n >= 8 else '\\fontsize{8.5}{11}\\selectfont'
        return '{' + size + '\n' + tb + '\n}'
    return re.sub(r'\\begin\{longtable\}.*?\\end\{longtable\}', one, t, flags=re.S)
body = style_tables(body)
body = re.sub(r'\\includegraphics\[[^\]]*\]', r'\\includegraphics[width=\\linewidth]', body)

# contents list
heads = re.findall(r'(?m)^## (.+)$', md)
items = []
for h in heads:
    items.append('\\item ' + h.replace('Appendix A. ', 'Appendix A: ').split('. ', 1)[-1] if re.match(r'\d+\. ', h) else '\\item[] ' + h)
contents = '\\begin{enumerate}[label=\\arabic*.,leftmargin=2.2em,itemsep=1pt]\n'
for h in heads:
    mo = re.match(r'(\d+)\. (.+)', h)
    if mo: contents += '\\item %s\n' % mo.group(2).replace('&', '\\&')
contents += '\\end{enumerate}\n'

def e(s): return s.replace('&', '\\&')
FALLBACK = '--fallback-mono' in sys.argv
need = ['fonts/RobotoMono-Regular.ttf', 'fonts/RobotoMono-Italic.ttf']
if not FALLBACK and not all(os.path.exists(f) for f in need):
    sys.exit('Roboto Mono TTF files not found in fonts/. See fonts/README.md, or run with --fallback-mono.')
main = r'''\newcommand{\fontdir}{fonts}
%(fb)s
\input{latex/preamble.tex}
\graphicspath{{./}}
\begin{document}
{\fontsize{20}{25}\bfseries\color{ink}\raggedright %(title)s\par}
\vspace{8pt}
{\fontsize{11}{14}\bfseries\noindent %(author)s \hfill %(field)s \hfill %(date)s\par}
\vspace{2pt}
\begingroup\setlength{\parskip}{4pt}
%(abstract)s
\endgroup
\begingroup\fontsize{9.5}{12.5}\selectfont\setlength{\parskip}{1pt}
%(meta)s
\endgroup
\vspace{4pt}
{\fontsize{15}{19}\bfseries\color{ink} Contents\par}
\vspace{3pt}
\begingroup\fontsize{10}{14}\selectfont
%(contents)s
\endgroup
%(body)s
\end{document}
''' % dict(title=e(title), author=author, field=field, date=date, abstract=abstract, meta=meta_tex, contents=contents, body=body, fb=('\\newcommand{\\fallbackmono}{}' if FALLBACK else ''))
# Contents rule above heading, as in the reference paper
main = main.replace('{\\fontsize{15}{19}\\bfseries\\color{ink} Contents\\par}',
                    '\\textcolor{ruleblue}{\\rule{\\linewidth}{0.7pt}}\\par\\vspace{6pt}\n{\\fontsize{15}{19}\\bfseries\\color{ink} Contents\\par}')
open(os.path.join(B, 'main.tex'), 'w').write(main)
for _ in range(2):
    r = subprocess.run(['xelatex', '-interaction=nonstopmode', '-halt-on-error', '-output-directory=' + B, os.path.join(B, 'main.tex')],
                       capture_output=True, text=True)
    if r.returncode:
        print(r.stdout[-3500:]); sys.exit('xelatex failed')
shutil.copy(os.path.join(B, 'main.pdf'), os.path.join(B, OUT + '.pdf'))
log = open(os.path.join(B, 'main.log'), errors='ignore').read()
print('Missing glyph warnings:', len(re.findall(r'Missing character', log)), '| Overfull boxes:', len(re.findall(r'Overfull \\hbox', log)))
print('built', os.path.join(B, OUT + '.pdf'))
