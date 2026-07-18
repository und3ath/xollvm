#!/usr/bin/env python3
"""cfg_svg.py — render obf-report CFG .dot files into clean, theme-safe SVG.

The obfuscation report (`-obf-report-dir`) emits one directory per function with
`before.dot`, `after.dot`, and `pass_<n>_<id>.dot` snapshots. Those DOT files use a
trivial subset:

    bb0 [label="entry\ninsts: 44", fillcolor="white", color="gray50", penwidth=1];
    bb0 -> bb1;

This tool parses that subset, runs a compact layered (Sugiyama-style) layout in pure
Python — no Graphviz dependency — and emits a single self-contained SVG that renders
well in both GitHub light and dark themes.

Node roles are accented:
  * entry      (in-degree 0)          → emerald
  * return/exit(out-degree 0)         → rose
  * dispatcher (top out-degree hub)   → amber, enlarged
  * injected   (block absent in the paired `before` graph) → cyan
  * retained   (everything else)      → indigo

Usage:
    # single graph
    python cfg_svg.py single after.dot -o out.svg --before before.dot \
        --title "After — CFG flattening" --subtitle "18 → 26 blocks"

    # combined before → after panel
    python cfg_svg.py pair before.dot after.dot -o out.svg \
        --title "CFG flattening" --left "Before · 18 blocks" --right "After · 26 blocks"
"""
from __future__ import annotations

import argparse
import html
import re
from collections import defaultdict, deque

NODE_RE = re.compile(r'^\s*(bb\d+)\s*\[label="([^"]*)"')
EDGE_RE = re.compile(r'^\s*(bb\d+)\s*->\s*(bb\d+)')

# ---- geometry -------------------------------------------------------------
NODE_W, NODE_H = 132, 46        # node box (height fixed so 2 text lines never collide)
H_GAP, V_GAP = 30, 74           # gaps between boxes (V_GAP tightened by --dense)
MARGIN = 40
BANNER = 108                    # title + subtitle + legend row
PANEL_LABEL = 30                # sub-caption above each panel in pair mode


# ---- parsing --------------------------------------------------------------
def parse_dot(path):
    nodes, edges, order = {}, [], []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = NODE_RE.match(line)
            if m:
                nid, label = m.group(1), m.group(2)
                parts = label.split("\\n")
                name = parts[0].strip() or nid
                insts = ""
                for p in parts[1:]:
                    p = p.strip()
                    if p.lower().startswith("insts"):
                        insts = p.split(":", 1)[-1].strip()
                if nid not in nodes:
                    order.append(nid)
                nodes[nid] = (name, insts)
                continue
            m = EDGE_RE.match(line)
            if m:
                edges.append((m.group(1), m.group(2)))
    for a, b in edges:
        for nid in (a, b):
            if nid not in nodes:
                nodes[nid] = (nid, "")
                order.append(nid)
    return nodes, edges, order


# ---- layout ---------------------------------------------------------------
def layer_assignment(nodes, edges):
    succ = defaultdict(list)
    indeg = defaultdict(int)
    for a, b in edges:
        succ[a].append(b)
        indeg[b] += 1
    entries = [n for n in nodes if indeg[n] == 0]
    root = entries[0] if entries else next(iter(nodes))

    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in nodes}
    back = set()
    roots = [root] + [n for n in nodes if n != root]
    for start in roots:
        if color[start] != WHITE:
            continue
        stack = [(start, iter(succ[start]))]
        color[start] = GRAY
        while stack:
            node, it = stack[-1]
            advanced = False
            for nxt in it:
                if color[nxt] == GRAY:
                    back.add((node, nxt))
                elif color[nxt] == WHITE:
                    color[nxt] = GRAY
                    stack.append((nxt, iter(succ[nxt])))
                    advanced = True
                    break
            if not advanced:
                color[node] = BLACK
                stack.pop()

    fwd = [(a, b) for (a, b) in edges if (a, b) not in back and a != b]
    fsucc = defaultdict(list)
    findeg = defaultdict(int)
    for a, b in fwd:
        fsucc[a].append(b)
        findeg[b] += 1
    rank = {n: 0 for n in nodes}
    q = deque([n for n in nodes if findeg[n] == 0])
    seen = defaultdict(int)
    while q:
        n = q.popleft()
        for m in fsucc[n]:
            if rank[n] + 1 > rank[m]:
                rank[m] = rank[n] + 1
            seen[m] += 1
            if seen[m] == findeg[m]:
                q.append(m)
    return rank, back


def order_within_layers(nodes, edges, rank, sweeps=6):
    layers = defaultdict(list)
    for n in nodes:
        layers[rank[n]].append(n)
    ranks = sorted(layers)
    for r in ranks:
        layers[r].sort()

    succ = defaultdict(list)
    pred = defaultdict(list)
    for a, b in edges:
        if a == b:
            continue
        succ[a].append(b)
        pred[b].append(a)

    def pos_map():
        return {n: i for r in ranks for i, n in enumerate(layers[r])}

    for s in range(sweeps):
        down = s % 2 == 0
        seq = ranks if down else ranks[::-1]
        pos = pos_map()
        for r in seq:
            neigh = pred if down else succ
            def key(n):
                ps = [pos[m] for m in neigh[n] if m in pos]
                return (sum(ps) / len(ps)) if ps else pos[n]
            layers[r] = sorted(layers[r], key=key)
            pos = pos_map()
    return layers, ranks


def classify(nid, nodes, edges, before_names):
    name = nodes[nid][0]
    outd = sum(1 for a, _ in edges if a == nid)
    ind = sum(1 for _, b in edges if b == nid)
    if ind == 0:
        return "entry"
    if outd == 0:
        return "exit"
    if before_names is not None and name not in before_names:
        return "inject"
    return "keep"


PALETTE = {
    "entry":  ("#34d399", "#059669", "#065f46"),
    "exit":   ("#fb7185", "#e11d48", "#881337"),
    "disp":   ("#fbbf24", "#f59e0b", "#92400e"),
    "inject": ("#22d3ee", "#0891b2", "#0e7490"),
    "keep":   ("#818cf8", "#6366f1", "#3730a3"),
}
LEGEND = [("entry", "entry"), ("keep", "original"), ("inject", "injected"),
          ("disp", "dispatcher"), ("exit", "return")]


# ---- drawing --------------------------------------------------------------
def graph_geometry(layers, ranks):
    """Return (positions-by-rank-index helper, width, height)."""
    max_cols = max((len(layers[r]) for r in ranks), default=1)
    gw = max_cols * NODE_W + (max_cols - 1) * H_GAP
    gh = len(ranks) * NODE_H + (len(ranks) - 1) * V_GAP
    return gw, gh


def place(layers, ranks, ox, oy, gw):
    pos = {}
    for i, r in enumerate(ranks):
        row = layers[r]
        row_w = len(row) * NODE_W + (len(row) - 1) * H_GAP
        x0 = ox + (gw - row_w) / 2
        y = oy + i * (NODE_H + V_GAP)
        for j, nid in enumerate(row):
            pos[nid] = (x0 + j * (NODE_W + H_GAP), y)
    return pos


def draw_graph(nodes, edges, back, layers, ranks, pos, before_names):
    rank_idx = {nid: i for i, r in enumerate(ranks) for nid in layers[r]}
    outdeg = defaultdict(int)
    for a, _ in edges:
        outdeg[a] += 1
    disp = None
    if outdeg:
        cand = max(outdeg, key=lambda n: outdeg[n])
        if outdeg[cand] >= 4:
            disp = cand

    def role(nid):
        if nid == disp:
            return "disp"
        return classify(nid, nodes, edges, before_names)

    def a_bot(n):
        x, y = pos[n]; return x + NODE_W / 2, y + NODE_H
    def a_top(n):
        x, y = pos[n]; return x + NODE_W / 2, y

    fwd_svg, back_svg = [], []
    for a, b in edges:
        if a not in pos or b not in pos:
            continue
        if a == b:
            x, y = pos[a]; cy = y + NODE_H / 2
            back_svg.append(
                f'<path d="M{x+NODE_W:.1f},{cy-8:.1f} C{x+NODE_W+34:.1f},{cy-24:.1f} '
                f'{x+NODE_W+34:.1f},{cy+24:.1f} {x+NODE_W:.1f},{cy+8:.1f}" fill="none" '
                f'stroke="#f59e0b" stroke-width="1.6" stroke-dasharray="4 3" marker-end="url(#arwb)"/>')
            continue
        is_back = (a, b) in back or rank_idx.get(a, 0) >= rank_idx.get(b, 0)
        if is_back:
            x1, y1 = a_top(a); x2, y2 = a_bot(b)
            mx = max(x1, x2) + 58
            back_svg.append(
                f'<path d="M{x1:.1f},{y1:.1f} C{mx:.1f},{y1:.1f} {mx:.1f},{y2:.1f} {x2:.1f},{y2:.1f}" '
                f'fill="none" stroke="#f59e0b" stroke-width="1.5" stroke-opacity="0.85" '
                f'stroke-dasharray="5 3" marker-end="url(#arwb)"/>')
        else:
            x1, y1 = a_bot(a); x2, y2 = a_top(b)
            if abs(x2 - x1) < 1.5:
                # straight vertical
                fwd_svg.append(
                    f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
                    f'stroke="var(--edge)" stroke-width="1.5" stroke-opacity="0.72" '
                    f'marker-end="url(#arw)"/>')
            else:
                # gentle S-curve whose END tangent points along src→dst so the
                # arrowhead aligns with the visible line (not straight down)
                dy = y2 - y1
                c1x, c1y = x1, y1 + dy * 0.5
                c2x, c2y = x1 + (x2 - x1) * 0.5, y2 - dy * 0.16
                fwd_svg.append(
                    f'<path d="M{x1:.1f},{y1:.1f} C{c1x:.1f},{c1y:.1f} {c2x:.1f},{c2y:.1f} {x2:.1f},{y2:.1f}" '
                    f'fill="none" stroke="var(--edge)" stroke-width="1.5" stroke-opacity="0.72" '
                    f'marker-end="url(#arw)"/>')

    node_svg = []
    for nid in nodes:
        if nid not in pos:
            continue
        x, y = pos[nid]
        r = role(nid)
        w, h = (NODE_W + 14, NODE_H + 4) if r == "disp" else (NODE_W, NODE_H)
        x -= (w - NODE_W) / 2
        y -= (h - NODE_H) / 2
        stroke = PALETTE[r][2]
        name, insts = nodes[nid]
        disp_name = name if len(name) <= 16 else name[:15] + "…"
        ty = y + (h / 2 - 6) if insts else y + h / 2
        node_svg.append(
            f'<g filter="url(#sh)"><rect x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" '
            f'rx="11" fill="url(#g_{r})" stroke="{stroke}" stroke-width="1.4"/>'
            f'<text class="bt" x="{x+w/2:.1f}" y="{ty:.1f}" text-anchor="middle" '
            f'font-size="12.5" dominant-baseline="middle">{html.escape(disp_name)}</text>')
        if insts:
            node_svg.append(
                f'<text class="bs" x="{x+w/2:.1f}" y="{y+h-9:.1f}" text-anchor="middle" '
                f'font-size="10">insts {html.escape(insts)}</text>')
        node_svg.append("</g>")

    return fwd_svg + back_svg + node_svg


def svg_defs_style():
    out = ["<defs>"]
    for role_name, (c1, c2, _) in PALETTE.items():
        out.append(
            f'<linearGradient id="g_{role_name}" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/>'
            f'</linearGradient>')
    out.append('<marker id="arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
               'markerHeight="7" orient="auto-start-reverse">'
               '<path d="M0,0 L10,5 L0,10 z" fill="var(--edge)"/></marker>')
    out.append('<marker id="arwb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
               'markerHeight="7" orient="auto-start-reverse">'
               '<path d="M0,0 L10,5 L0,10 z" fill="#f59e0b"/></marker>')
    out.append('<marker id="arwbig" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="9" '
               'markerHeight="9" orient="auto"><path d="M0,0 L12,6 L0,12 z" fill="#8b5cf6"/></marker>')
    out.append('<filter id="sh" x="-20%" y="-20%" width="140%" height="140%">'
               '<feDropShadow dx="0" dy="2" stdDeviation="2.4" flood-opacity="0.28"/></filter>')
    out.append("</defs>")
    out.append(
        "<style>"
        ":root{--bg:#0d1117;--edge:#8b98a5;--fg:#e6edf3;--sub:#93a1b0;--pl:#c9d4e0;}"
        "@media (prefers-color-scheme: light){:root{--bg:#ffffff;--edge:#94a3b8;--fg:#1e293b;--sub:#64748b;--pl:#334155;}}"
        ":root[data-theme='light']{--bg:#ffffff;--edge:#94a3b8;--fg:#1e293b;--sub:#64748b;--pl:#334155;}"
        ":root[data-theme='dark']{--bg:#0d1117;--edge:#8b98a5;--fg:#e6edf3;--sub:#93a1b0;--pl:#c9d4e0;}"
        ".bt{font-weight:700;fill:#fff;}.bs{fill:#eef2ff;opacity:.82;}"
        ".ttl{fill:var(--fg);font-weight:800;}.sub{fill:var(--sub);}.lg{fill:var(--sub);}"
        ".pl{fill:var(--pl);font-weight:700;}"
        "</style>")
    return out


def legend_svg(x_right, y):
    parts, xcur = [], x_right
    for role_name, lbl in reversed(LEGEND):
        wpx = 8 + 6.6 * len(lbl) + 20
        xcur -= wpx
        parts.append((xcur, role_name, lbl))
    out = []
    for xc, role_name, lbl in parts:
        out.append(f'<rect x="{xc:.0f}" y="{y-10}" width="12" height="12" rx="3" fill="{PALETTE[role_name][0]}"/>')
        out.append(f'<text class="lg" x="{xc+17:.0f}" y="{y}" font-size="12.5">{html.escape(lbl)}</text>')
    return out


def frame(canvas_w, canvas_h, title, subtitle, body):
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}" '
        f'width="{canvas_w:.0f}" height="{canvas_h:.0f}" '
        f'font-family="ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif">']
    out += svg_defs_style()
    out.append(f'<rect x="0" y="0" width="{canvas_w:.0f}" height="{canvas_h:.0f}" rx="14" fill="var(--bg)"/>')
    out.append(f'<text class="ttl" x="{MARGIN}" y="44" font-size="25">{html.escape(title)}</text>')
    if subtitle:
        out.append(f'<text class="sub" x="{MARGIN}" y="69" font-size="14.5">{html.escape(subtitle)}</text>')
    out += legend_svg(canvas_w - MARGIN, 96)     # legend on its own row → never hits subtitle
    out += body
    out.append("</svg>")
    return "\n".join(out)


def render_single(dotpath, before_path, title, subtitle):
    nodes, edges, _ = parse_dot(dotpath)
    before_names = None
    if before_path:
        bn, _, _ = parse_dot(before_path)
        before_names = {v[0] for v in bn.values()}
    rank, back = layer_assignment(nodes, edges)
    layers, ranks = order_within_layers(nodes, edges, rank)
    gw, gh = graph_geometry(layers, ranks)
    canvas_w = max(gw + 2 * MARGIN, 760)
    canvas_h = BANNER + gh + MARGIN
    pos = place(layers, ranks, (canvas_w - gw) / 2, BANNER, gw)
    body = draw_graph(nodes, edges, back, layers, ranks, pos, before_names)
    return frame(canvas_w, canvas_h, title, subtitle, body)


def render_pair(before_path, after_path, title, subtitle, left_cap, right_cap, stack=False):
    bn, be, _ = parse_dot(before_path)
    an, ae, _ = parse_dot(after_path)
    before_names = {v[0] for v in bn.values()}

    br, bback = layer_assignment(bn, be)
    bl, brk = order_within_layers(bn, be, br)
    bgw, bgh = graph_geometry(bl, brk)

    ar, aback = layer_assignment(an, ae)
    al, ark = order_within_layers(an, ae, ar)
    agw, agh = graph_geometry(al, ark)

    if stack:
        ARROW_V = 62
        boy = BANNER + PANEL_LABEL
        aoy = boy + bgh + ARROW_V + PANEL_LABEL
        canvas_w = MARGIN + max(bgw, agw) + MARGIN
        canvas_h = aoy + agh + MARGIN
        cx = canvas_w / 2
        bpos = place(bl, brk, (canvas_w - bgw) / 2, boy, bgw)
        apos = place(al, ark, (canvas_w - agw) / 2, aoy, agw)
        body = []
        body.append(f'<text class="pl" x="{cx:.0f}" y="{boy-10:.0f}" text-anchor="middle" font-size="15">{html.escape(left_cap)}</text>')
        body.append(f'<text class="pl" x="{cx:.0f}" y="{aoy-10:.0f}" text-anchor="middle" font-size="15">{html.escape(right_cap)}</text>')
        body += draw_graph(bn, be, bback, bl, brk, bpos, None)
        body += draw_graph(an, ae, aback, al, ark, apos, before_names)
        ay1 = boy + bgh + 12
        ay2 = aoy - PANEL_LABEL - 4
        body.append(f'<line x1="{cx:.0f}" y1="{ay1:.0f}" x2="{cx:.0f}" y2="{ay2:.0f}" '
                    f'stroke="#8b5cf6" stroke-width="3.5" marker-end="url(#arwbig)"/>')
        body.append(f'<text x="{cx+10:.0f}" y="{(ay1+ay2)/2+4:.0f}" '
                    f'fill="#8b5cf6" font-weight="700" font-size="12.5">obfuscate</text>')
        return frame(canvas_w, canvas_h, title, subtitle, body)

    ARROW = 96
    oy = BANNER + PANEL_LABEL
    canvas_w = MARGIN + bgw + ARROW + agw + MARGIN
    canvas_h = oy + max(bgh, agh) + MARGIN

    bpos = place(bl, brk, MARGIN, oy, bgw)
    apos = place(al, ark, MARGIN + bgw + ARROW, oy, agw)
    body = []
    body.append(f'<text class="pl" x="{MARGIN + bgw/2:.0f}" y="{oy-10:.0f}" text-anchor="middle" font-size="15">{html.escape(left_cap)}</text>')
    body.append(f'<text class="pl" x="{MARGIN + bgw + ARROW + agw/2:.0f}" y="{oy-10:.0f}" text-anchor="middle" font-size="15">{html.escape(right_cap)}</text>')
    body += draw_graph(bn, be, bback, bl, brk, bpos, None)
    body += draw_graph(an, ae, aback, al, ark, apos, before_names)
    ay = oy + min(bgh, agh) / 2
    ax1 = MARGIN + bgw + 20
    ax2 = MARGIN + bgw + ARROW - 20
    body.append(f'<line x1="{ax1:.0f}" y1="{ay:.0f}" x2="{ax2:.0f}" y2="{ay:.0f}" '
                f'stroke="#8b5cf6" stroke-width="3.5" marker-end="url(#arwbig)"/>')
    body.append(f'<text x="{(ax1+ax2)/2:.0f}" y="{ay-12:.0f}" text-anchor="middle" '
                f'fill="#8b5cf6" font-weight="700" font-size="12.5">obfuscate</text>')
    return frame(canvas_w, canvas_h, title, subtitle, body)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("single")
    s.add_argument("dot")
    s.add_argument("-o", "--out", required=True)
    s.add_argument("--before")
    s.add_argument("--title", default="CFG")
    s.add_argument("--subtitle", default="")
    s.add_argument("--dense", action="store_true")

    p = sub.add_parser("pair")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--title", default="CFG transform")
    p.add_argument("--subtitle", default="")
    p.add_argument("--left", default="Before")
    p.add_argument("--right", default="After")
    p.add_argument("--dense", action="store_true")
    p.add_argument("--stack", action="store_true",
                   help="stack before above after (good for wide graphs)")

    a = ap.parse_args()
    if getattr(a, "dense", False):
        global V_GAP, H_GAP
        V_GAP, H_GAP = 40, 22

    if a.cmd == "single":
        svg = render_single(a.dot, a.before, a.title, a.subtitle)
    else:
        svg = render_pair(a.before, a.after, a.title, a.subtitle, a.left, a.right,
                          stack=a.stack)
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
