#!/usr/bin/env python3
"""Draw the three figures for the flagship article. Numbers are copied from the
evidence cited in the article (Sections 9 and 12); nothing is estimated."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib import font_manager as fm
import os, sys
out = sys.argv[1] if len(sys.argv) > 1 else 'figures'
os.makedirs(out, exist_ok=True)
for f in ['/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf','/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf','/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf']:
    fm.fontManager.addfont(f)
plt.rcParams['font.family'] = 'Liberation Sans'
INK, NAVY, RULE, FILL, MUTED, BLUE, GRAY = '#1F2933', '#2C3E50', '#C3CBD6', '#E8EDF3', '#3E4C59', '#2C5F8A', '#8A96A3'

def box(ax, x, y, w, h, title, sub=None, fc='white', ec=NAVY, lw=1.2, tsize=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.0,rounding_size=0.06', fc=fc, ec=ec, lw=lw))
    if sub:
        ax.text(x + w/2, y + h*0.64, title, ha='center', va='center', fontsize=tsize, fontweight='bold', color=INK)
        ax.text(x + w/2, y + h*0.28, sub, ha='center', va='center', fontsize=6.8, color=MUTED, linespacing=1.25)
    else:
        ax.text(x + w/2, y + h/2, title, ha='center', va='center', fontsize=tsize, fontweight='bold', color=INK)

def arrow(ax, x1, y1, x2, y2, color=NAVY, style='-|>', ls='-'):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=9, lw=1.1, color=color, linestyle=ls, shrinkA=0, shrinkB=0))

# Figure 1: pipeline
fig, ax = plt.subplots(figsize=(6.5, 3.15))
ax.set_xlim(0, 13); ax.set_ylim(0, 6.3); ax.axis('off')
ax.add_patch(FancyBboxPatch((0.05, 3.0), 2.7, 3.15, boxstyle='round,pad=0,rounding_size=0.08', fc=FILL, ec=RULE, lw=1))
ax.text(1.4, 5.85, 'Kernel', ha='center', fontsize=7.5, color=MUTED, fontweight='bold')
box(ax, 0.25, 4.15, 2.3, 1.35, '12 programs', 'tracepoints, 5 maps\n4 MiB ring buffer')
ax.add_patch(FancyBboxPatch((2.95, 3.0), 10.0, 3.15, boxstyle='round,pad=0,rounding_size=0.08', fc='white', ec=RULE, lw=1))
ax.text(7.95, 5.85, 'User space: JSON lines between stages', ha='center', fontsize=7.5, color=MUTED, fontweight='bold')
box(ax, 3.15, 4.15, 1.7, 1.35, 'loader', 'C, libbpf\nattach, poll 200 ms')
box(ax, 5.25, 4.15, 1.9, 1.35, 'normalizer', 'Python\nprocess key, exec join')
box(ax, 7.55, 4.15, 3.0, 1.35, 'runner', 'process graph, 10 detectors\nin order, ATT&CK lookup')
box(ax, 10.95, 4.15, 1.85, 1.35, 'alert sink', 'JSON line and\nreadable block')
for x1, x2 in [(2.55, 3.15), (4.85, 5.25), (7.15, 7.55), (10.55, 10.95)]:
    arrow(ax, x1, 4.82, x2, 4.82)
ax.text(5.05, 5.0, 'raw', fontsize=6.3, color=MUTED, ha='center')
ax.text(7.0, 2.55, 'Added by the evaluation harness', fontsize=7.5, color=MUTED, fontweight='bold')
box(ax, 3.45, 0.55, 1.5, 1.4, 'tee', 'saves\nevents.jsonl', fc=FILL, ec=GRAY, lw=1.0, tsize=8)
box(ax, 5.6, 0.55, 1.9, 1.4, 'tee', 'saves\nnormalized.jsonl', fc=FILL, ec=GRAY, lw=1.0, tsize=8)
box(ax, 11.05, 0.55, 1.65, 1.4, 'stamper', 'arrival time\nper alert', fc=FILL, ec=GRAY, lw=1.0, tsize=8)
arrow(ax, 4.0, 4.15, 4.2, 1.95, color=GRAY, style='-|>', ls='--')
arrow(ax, 6.2, 4.15, 6.55, 1.95, color=GRAY, style='-|>', ls='--')
arrow(ax, 11.9, 4.15, 11.9, 1.95, color=GRAY, style='-|>', ls='--')
ax.text(9.0, 1.25, 'Six stages in all: loader, normalizer,\nrunner, two tees, stamper', fontsize=6.8, color=MUTED, ha='center', va='center')
fig.subplots_adjust(0.01, 0.01, 0.99, 0.99)
fig.savefig(f'{out}/fig1-pipeline.png', dpi=220); fig.savefig(f'{out}/fig1-pipeline.svg'); plt.close(fig)

# Figure 2: detection by group, and benign alerts
fig, (a, b) = plt.subplots(1, 2, figsize=(6.5, 2.7), gridspec_kw={'width_ratios': [1.15, 1]})
groups = ['Original\nordinary (18)', 'Original\ngap (10)', 'Threat-model\nset (8)']
det = [18, 0, 2]; tot = [18, 10, 8]
x = range(3)
a.bar(x, tot, color='white', edgecolor=GRAY, lw=1.0, width=0.55, label='Scenarios')
a.bar(x, det, color=BLUE, width=0.55, label='Detected')
for i in x:
    a.text(i, tot[i] + 0.5, f'{det[i]} of {tot[i]}', ha='center', fontsize=8, color=INK, fontweight='bold')
a.set_xticks(list(x)); a.set_xticklabels(groups, fontsize=7.5, color=INK); a.set_ylim(0, 22); a.set_yticks([0,5,10,15,20])
a.set_ylabel('Scenarios', fontsize=8, color=MUTED); a.tick_params(axis='y', labelsize=7.5, colors=MUTED)
a.set_title('Attack scenarios detected', fontsize=8.5, fontweight='bold', color=INK, loc='left')
a.legend(fontsize=7, frameon=False, loc='upper right')
runs = ['Near-miss\n(8 scen.)', 'Everyday\n101', 'Everyday\n102', 'Everyday\n103']
alerts = [5, 154, 158, 154]
b.bar(range(4), alerts, color=[GRAY, BLUE, BLUE, BLUE], width=0.55)
for i, v in enumerate(alerts):
    b.text(i, v + 4, str(v), ha='center', fontsize=8, color=INK, fontweight='bold')
b.set_xticks(range(4)); b.set_xticklabels(runs, fontsize=7.5, color=INK); b.set_ylim(0, 185)
b.set_ylabel('Alerts (all false)', fontsize=8, color=MUTED); b.tick_params(axis='y', labelsize=7.5, colors=MUTED)
b.set_title('Alerts on benign activity', fontsize=8.5, fontweight='bold', color=INK, loc='left')
for ax_ in (a, b):
    for s in ('top', 'right'): ax_.spines[s].set_visible(False)
    for s in ('left', 'bottom'): ax_.spines[s].set_color(RULE)
fig.tight_layout(pad=0.6, w_pad=1.6)
fig.savefig(f'{out}/fig2-results.png', dpi=220); fig.savefig(f'{out}/fig2-results.svg'); plt.close(fig)

# Figure 3: stress CPU and RSS
rate = [100, 250, 500, 1000, 2000, 3999.4]
ld = [0.516, 1.177, 1.998, 4.203, 7.582, 13.474]
nm = [1.687, 3.602, 6.442, 14.226, 24.951, 42.697]
rn = [2.031, 4.564, 8.888, 20.426, 37.839, 70.059]
rss = [27200, 44640, 74208, 130264, 218412, 235108]
fig, (a, b) = plt.subplots(1, 2, figsize=(6.5, 2.7))
a.plot(rate, rn, marker='o', ms=3.5, lw=1.4, color=BLUE, label='runner')
a.plot(rate, nm, marker='s', ms=3.5, lw=1.4, color=NAVY, label='normalizer')
a.plot(rate, ld, marker='^', ms=3.5, lw=1.4, color=GRAY, label='loader')
a.set_xlabel('Achieved executions per second', fontsize=8, color=MUTED); a.set_ylabel('CPU, percent of one core (mean)', fontsize=8, color=MUTED)
a.set_title('CPU by process', fontsize=8.5, fontweight='bold', color=INK, loc='left'); a.legend(fontsize=7, frameon=False, loc='upper left')
b.plot(rate, [v/1000 for v in rss], marker='o', ms=3.5, lw=1.4, color=BLUE)
b.set_ylim(0, 260); b.set_xlabel('Achieved executions per second', fontsize=8, color=MUTED); b.set_ylabel('Runner max RSS (MB, 1 MB = 1000 kB)', fontsize=8, color=MUTED)
b.set_title('Runner memory', fontsize=8.5, fontweight='bold', color=INK, loc='left')
for ax_ in (a, b):
    ax_.tick_params(labelsize=7.5, colors=MUTED); ax_.grid(axis='y', color='#E8EDF3', lw=0.8)
    for s in ('top', 'right'): ax_.spines[s].set_visible(False)
    for s in ('left', 'bottom'): ax_.spines[s].set_color(RULE)
fig.tight_layout(pad=0.6, w_pad=1.8)
fig.savefig(f'{out}/fig3-stress.png', dpi=220); fig.savefig(f'{out}/fig3-stress.svg'); plt.close(fig)
print('ok')
