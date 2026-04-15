#!/usr/bin/env python3
"""Generate a standalone HTML report from llvm_obfuscator's JSON obfuscation map.

Usage:
  python3 llvm/utils/obf_report_html.py --json <path/to/obf_report.json> --out <report.html>

If your JSON was produced with -obf-report-dir, CFG DOT artifacts referenced in
JSON are expected to live under that directory. If --report-dir is omitted, the
script assumes it's the directory containing the JSON.

Renderers:
  auto (default): use Cytoscape when DOT artifacts are available; otherwise use
                  Graphviz `dot` if installed, else browser-side Graphviz WASM.
  cyto:           interactive Cytoscape.js viewer (pan/zoom, drag nodes, layouts, click-to-inspect)
                  (requires DOT artifacts; uses CDN)
  dot:            render DOT -> inline SVG server-side (requires `dot` in PATH)
  wasm:           render DOT -> SVG in the browser via d3-graphviz + Graphviz WASM
  text:           show DOT sources as text

This script also provides:
  • Pan/zoom for all rendered CFGs
  • Clickable CFG nodes: shows BB metadata / IR (from DOT tooltips) in an inspector

Note: For the BB IR inspector to be useful, DOT node tooltips should include
      per-BB info. The in-tree obfuscator's CFG DOT writer can embed this.
"""

from __future__ import annotations

import argparse
import html
import json
import shutil
import subprocess
import sys
import json as _json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _read_json(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Top-level JSON must be an object")
    return data


def _find_dot() -> Optional[str]:
    return shutil.which("dot")


def _report_has_dot_artifacts(data: Dict[str, Any], report_dir: Path) -> bool:
    """Best-effort: check whether any referenced CFG DOT artifacts exist on disk."""
    try:
        funcs = data.get("functions", [])
        if not isinstance(funcs, list):
            return False

        for f in funcs:
            if not isinstance(f, dict):
                continue
            artifacts = f.get("artifacts", {}) if isinstance(f.get("artifacts"), dict) else {}
            cfg = artifacts.get("cfg", {}) if isinstance(artifacts.get("cfg"), dict) else {}
            if not isinstance(cfg, dict):
                continue

            rels: List[str] = []
            for k in ("before_dot", "after_dot"):
                v = cfg.get(k)
                if isinstance(v, str) and v:
                    rels.append(v)

            per_pass = cfg.get("per_pass", [])
            if isinstance(per_pass, list):
                for stage in per_pass:
                    if not isinstance(stage, dict):
                        continue
                    for k in ("diff_dot", "after_dot", "before_dot"):
                        v = stage.get(k)
                        if isinstance(v, str) and v:
                            rels.append(v)

            for rel in rels:
                if rel.lower().endswith(".dot") and (report_dir / rel).exists():
                    return True
        return False
    except Exception:
        return False



def _pick_renderer(requested: str, dot_exe: Optional[str], has_dot_artifacts: bool) -> str:
    r = (requested or "auto").strip().lower()
    if r == "auto":
        if has_dot_artifacts:
            return "cyto"
        return "dot" if dot_exe else "wasm"
    if r in ("cyto", "dot", "wasm", "text"):
        return r
    return "auto"



def _dot_to_svg(dot_exe: str, dot_path: Path) -> Optional[str]:
    try:
        p = subprocess.run(
            [dot_exe, "-Tsvg", str(dot_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if p.returncode != 0:
            return None
        return p.stdout
    except Exception:
        return None


def _load_dot_or_svg(report_dir: Path, rel_path: str, dot_exe: Optional[str]) -> Tuple[str, str]:
    """Returns (kind, payload) where kind is 'svg' or 'dot' or 'missing'."""
    if not rel_path:
        return ("missing", "")
    abs_path = report_dir / rel_path
    if not abs_path.exists():
        return ("missing", f"Missing: {abs_path}")

    if dot_exe:
        svg = _dot_to_svg(dot_exe, abs_path)
        if svg:
            return ("svg", svg)

    try:
        dot_src = abs_path.read_text(encoding="utf-8", errors="replace")
        return ("dot", dot_src)
    except Exception as e:
        return ("missing", f"Failed to read: {abs_path} ({e})")


def _fmt_pct(x: float) -> str:
    try:
        return f"{x*100.0:.1f}%"
    except Exception:
        return ""


def _safe(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _svg_viewer(payload_html: str, rel: str, *, extra_style: str = "") -> str:
    st = f" style='{_safe(extra_style)}'" if extra_style else ""
    link = ""
    if rel:
        link = (
            "<a class='svgLink' href='" + _safe(rel) +
            "' target='_blank' rel='noopener'>open artifact</a>"
        )
    return (
        f"<div class='svgWrap' data-svgviewer='1'{st}>"
        "<div class='svgTools'>"
        "<div class='svgBtns'>"
        "<button class='svgBtn' type='button' data-svg-zoom-in title='Zoom in'>+</button>"
        "<button class='svgBtn' type='button' data-svg-zoom-out title='Zoom out'>−</button>"
        "<button class='svgBtn' type='button' data-svg-reset title='Reset view'>reset</button>"
        "</div>"
        "<span class='muted'>drag to pan • wheel to zoom</span>"
        f"{link}"
        "</div>"
        f"<div class='svgViewport'>{payload_html}</div>"
        "</div>"
    )


def _cy_viewer(dom_id: str, rel: str, *, extra_style: str = "") -> str:
    st = f" style='{_safe(extra_style)}'" if extra_style else ""
    link = ""
    if rel:
        link = (
            "<a class='svgLink' href='" + _safe(rel) +
            "' target='_blank' rel='noopener'>open artifact</a>"
        )
    return (
        f"<div class='cyWrap' data-cyviewer='1' data-cyid='{_safe(dom_id)}'{st}>"
        "<div class='cyTools'>"
        "<div class='cyLeft'>"
        "<select class='cySelect' data-cy-layout title='Layout'>"
        "<option value='dagre'>dagre</option>"
        "<option value='breadthfirst'>breadthfirst</option>"
        "<option value='concentric'>concentric</option>"
        "<option value='circle'>circle</option>"
        "<option value='grid'>grid</option>"
        "</select>"
        "<button class='cyBtn' type='button' data-cy-run-layout title='Re-run layout'>layout</button>"
        "<button class='cyBtn' type='button' data-cy-fit title='Fit to screen'>fit</button>"
        "<button class='cyBtn' type='button' data-cy-clear title='Clear selection'>clear</button>"
        "</div>"
        "<input class='cySearch' type='search' placeholder='find node…' data-cy-search>"
        f"{link}"
        "</div>"
        f"<div id='{_safe(dom_id)}' class='cyViewport'></div>"
        "</div>"
    )




def _budget_bar(util: Optional[float]) -> str:
    if util is None:
        return ""
    try:
        v = float(util)
    except Exception:
        return ""
    pct = max(0.0, min(2.0, v)) * 100.0
    return (
        f'<div class="bar"><div class="barFill" style="width:{pct:.1f}%"></div></div>'
        f'<span class="muted">{_safe(_fmt_pct(v))}</span>'
    )


def build_html(data: Dict[str, Any], report_dir: Path, renderer: str) -> str:
    dot_exe = _find_dot()
    has_dot_artifacts = _report_has_dot_artifacts(data, report_dir)
    renderer = _pick_renderer(renderer, dot_exe, has_dot_artifacts)

    cyto_mode = (renderer == "cyto")
    dot_mode = (renderer == "dot" and dot_exe is not None)
    wasm_mode = (renderer == "wasm")
    text_mode = (renderer == "text")

    schema = data.get("schema")
    version = data.get("schema_version")
    module = data.get("module", {}) if isinstance(data.get("module"), dict) else {}
    functions = data.get("functions", [])
    if not isinstance(functions, list):
        functions = []

    def _fn_name(f: Any) -> str:
        return str(f.get("name", "")) if isinstance(f, dict) else ""

    functions = sorted(functions, key=_fn_name)

    total = len(functions)
    skipped = sum(1 for f in functions if isinstance(f, dict) and f.get("skipped") is True)

    css = r"""
:root { color-scheme: light dark; }
body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial; margin: 0; }
header { position: sticky; top: 0; backdrop-filter: blur(8px); background: rgba(250,250,250,.85); border-bottom: 1px solid rgba(0,0,0,.08); padding: 16px 20px; z-index: 10; }
header h1 { margin: 0; font-size: 18px; }
header .meta { margin-top: 6px; font-size: 12px; opacity: .75; }
main { padding: 18px 20px 64px; }
.controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 12px 0 18px; }
input[type=search] { padding: 10px 12px; border-radius: 10px; border: 1px solid rgba(0,0,0,.18); min-width: 280px; }
.badge { font-size: 12px; padding: 4px 8px; border-radius: 999px; border: 1px solid rgba(0,0,0,.18); }
.card { border: 1px solid rgba(0,0,0,.16); border-radius: 16px; padding: 14px 14px; margin: 12px 0; box-shadow: 0 2px 12px rgba(0,0,0,.05); }
.card h2 { font-size: 15px; margin: 0 0 6px; display: flex; gap: 10px; align-items: center; }
.card .row { display: flex; gap: 16px; flex-wrap: wrap; align-items: center; font-size: 13px; }
.kv { display: inline-flex; gap: 6px; align-items: baseline; }
.kv .k { opacity: .70; }
.kv .v { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
.muted { opacity: .70; font-size: 12px; }
.pills { display: flex; gap: 6px; flex-wrap: wrap; }
.pill { font-size: 12px; padding: 3px 8px; border-radius: 999px; background: rgba(0,0,0,.06); border: 1px solid rgba(0,0,0,.10); }
.table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
.table th, .table td { text-align: left; padding: 7px 8px; border-bottom: 1px solid rgba(0,0,0,.10); }
.table th { opacity: .8; font-weight: 600; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 10px; }
.grid2 > * { min-width: 0; }
@media (max-width: 1100px) { .grid2 { grid-template-columns: 1fr; } }
.svgWrap { border: 1px solid rgba(0,0,0,.12); border-radius: 14px; padding: 10px; background: rgba(0,0,0,.02); }
.svgTools { display:flex; gap:10px; align-items:center; justify-content:space-between; flex-wrap:wrap; margin-bottom: 8px; }
.svgBtns { display:flex; gap:6px; align-items:center; }
.svgBtn { font-size: 12px; padding: 4px 8px; border-radius: 10px; border: 1px solid rgba(0,0,0,.18); background: rgba(0,0,0,.03); color: inherit; cursor: pointer; }
.svgBtn:hover { background: rgba(0,0,0,.08); }
.svgLink { font-size: 12px; opacity: .80; text-decoration: none; }
.svgLink:hover { text-decoration: underline; }
.svgViewport { width: 100%; height: min(520px, 65vh); overflow: hidden; border-radius: 12px; border: 1px solid rgba(0,0,0,.10); background: rgba(0,0,0,.02); cursor: grab; }
.svgViewport.dragging { cursor: grabbing; }
.svgViewport svg { width: 100%; height: 100%; }
.svgViewport svg .node { cursor: pointer; }
.svgViewport svg .node.selected polygon,
.svgViewport svg .node.selected ellipse { stroke-width: 3; }
.cyWrap { border: 1px solid rgba(0,0,0,.12); border-radius: 14px; padding: 10px; background: rgba(0,0,0,.02); min-width: 0; }
.cyTools { display:flex; gap:10px; align-items:center; justify-content:space-between; flex-wrap:wrap; margin-bottom: 8px; }
.cyLeft { display:flex; gap:6px; align-items:center; }
.cyBtn { font-size: 12px; padding: 4px 8px; border-radius: 10px; border: 1px solid rgba(0,0,0,.18); background: rgba(0,0,0,.03); color: inherit; cursor: pointer; }
.cyBtn:hover { background: rgba(0,0,0,.08); }
.cySelect { font-size: 12px; padding: 4px 8px; border-radius: 10px; border: 1px solid rgba(0,0,0,.18); background: rgba(0,0,0,.03); color: inherit; }
.cySearch { font-size: 12px; padding: 4px 8px; border-radius: 10px; border: 1px solid rgba(0,0,0,.18); background: rgba(0,0,0,.03); color: inherit; min-width: 180px; }
.cyViewport { width: 100%; height: min(520px, 65vh); overflow: hidden; border-radius: 12px; border: 1px solid rgba(0,0,0,.10); background: rgba(0,0,0,.02); position: relative; }
.cyViewport canvas { width: 100% !important; height: 100% !important; }
.cyViewport > div { width: 100% !important; height: 100% !important; }

pre { white-space: pre; overflow: auto; padding: 10px; border-radius: 14px; border: 1px solid rgba(0,0,0,.12); background: rgba(0,0,0,.02); }
.bar { width: 140px; height: 8px; border-radius: 999px; background: rgba(0,0,0,.10); overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 8px; }
.barFill { height: 100%; background: rgba(0,0,0,.55); }
details summary { cursor: pointer; }
hr { border: 0; border-top: 1px solid rgba(0,0,0,.12); margin: 14px 0; }

/* BB inspector */
#bbInspector { position: fixed; right: 16px; bottom: 16px; width: min(680px, calc(100vw - 32px)); max-height: min(70vh, 720px);
  overflow: hidden; border-radius: 16px; border: 1px solid rgba(0,0,0,.18);
  background: rgba(250,250,250,.92); backdrop-filter: blur(10px);
  box-shadow: 0 12px 40px rgba(0,0,0,.20); display: none; z-index: 50; }
#bbInspector.open { display: block; }
#bbInspector .hdr { display:flex; align-items:center; justify-content:space-between; gap: 10px; padding: 10px 12px; border-bottom: 1px solid rgba(0,0,0,.12); }
#bbInspector .hdr .title { font-size: 13px; }
#bbInspector .hdr .title .v { margin-left: 8px; }
#bbInspector .hdr button { border: 1px solid rgba(0,0,0,.18); background: rgba(0,0,0,.03); color: inherit; border-radius: 10px; padding: 2px 8px; cursor: pointer; }
#bbInspector .hdr button:hover { background: rgba(0,0,0,.08); }
#bbInspector .body { padding: 10px 12px; overflow: auto; max-height: calc(min(70vh, 720px) - 44px); }
#bbInspector .body pre { margin: 10px 0 0; max-height: 45vh; }

@media (prefers-color-scheme: dark) {
  header { background: rgba(18,18,18,.72); border-bottom: 1px solid rgba(255,255,255,.12); }
  .card { border: 1px solid rgba(255,255,255,.14); box-shadow: 0 2px 12px rgba(0,0,0,.35); }
  input[type=search] { border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.06); color: inherit; }
  .badge { border: 1px solid rgba(255,255,255,.18); }
  .pill { background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.12); }
  .svgWrap, pre { border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); }
  .svgBtn { border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.06); }
  .svgBtn:hover { background: rgba(255,255,255,.12); }
  .svgViewport { border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.06); }
  .bar { background: rgba(255,255,255,.14); }
  .barFill { background: rgba(255,255,255,.60); }
  #bbInspector { border: 1px solid rgba(255,255,255,.18); background: rgba(18,18,18,.85); }
  #bbInspector .hdr { border-bottom: 1px solid rgba(255,255,255,.14); }
  #bbInspector .hdr button { border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.06); }
  #bbInspector .hdr button:hover { background: rgba(255,255,255,.12); }
}
"""

    js = r"""
const __OBF_RENDERER = "__RENDERER__";

function filterFunctions() {
  const q = (document.getElementById('search').value || '').toLowerCase();
  const cards = document.querySelectorAll('.fnCard');
  for (const c of cards) {
    const name = (c.getAttribute('data-name') || '').toLowerCase();
    c.style.display = name.includes(q) ? '' : 'none';
  }
}

function __bbInspectorOpen(id, label, tooltip) {
  const pane = document.getElementById('bbInspector');
  if (!pane) return;
  const idEl = document.getElementById('bbInspectorId');
  const labelEl = document.getElementById('bbInspectorLabel');
  const bodyEl = document.getElementById('bbInspectorBody');

  if (idEl) idEl.textContent = id || '';
  if (labelEl) labelEl.textContent = label || '';
  if (bodyEl) {
    let t = tooltip || '';
    // Normalize escaped newlines commonly seen in DOT tooltips.
    t = t.replace(/\\n/g, '\n');
    bodyEl.textContent = t;
  }
  pane.classList.add('open');
}

function __bbInspectorClose() {
  const pane = document.getElementById('bbInspector');
  if (!pane) return;
  pane.classList.remove('open');
}

function __wireSvgForClicks(svg) {
  if (!svg) return;
  const nodes = svg.querySelectorAll('g.node');
  if (!nodes || nodes.length === 0) return;

  nodes.forEach((node) => {
    if (node.dataset.bbWired === '1') return;
    node.dataset.bbWired = '1';
    node.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();

      // Selection highlight.
      nodes.forEach((n) => n.classList.remove('selected'));
      node.classList.add('selected');

      const id = node.getAttribute('id') || '';
      const titleEl = node.querySelector('title');
      const tooltip = titleEl ? (titleEl.textContent || '') : '';

      // Label text may be split across multiple <text> nodes.
      const labelParts = Array.from(node.querySelectorAll('text')).map(t => t.textContent || '');
      const label = labelParts.join('\n').trim();

      __bbInspectorOpen(id, label, tooltip);
    });
  });
}

function __svgInitOne(wrap) {
  if (!wrap || wrap.dataset.svgInited === '1') return;
  const viewport = wrap.querySelector('.svgViewport');
  const svg = viewport ? viewport.querySelector('svg') : null;
  if (!viewport || !svg) return; // may be wasm-rendered later

  // Wire BB inspector click hooks.
  __wireSvgForClicks(svg);

  // Ensure there's a viewBox we can manipulate.
  const origVB = svg.getAttribute('viewBox');
  if (!origVB) {
    const rw = parseFloat(svg.getAttribute('width') || '') || svg.clientWidth || 100;
    const rh = parseFloat(svg.getAttribute('height') || '') || svg.clientHeight || 100;
    svg.setAttribute('viewBox', `0 0 ${rw} ${rh}`);
  }

  const vb0 = (svg.getAttribute('viewBox') || '0 0 100 100').trim().split(/\s+/).map(parseFloat);
  let x0 = vb0[0] || 0, y0 = vb0[1] || 0, w0 = vb0[2] || 100, h0 = vb0[3] || 100;
  let x = x0, y = y0, w = w0, h = h0;

  const setVB = () => svg.setAttribute('viewBox', `${x} ${y} ${w} ${h}`);

  function zoom(factor, clientX, clientY) {
    const rect = viewport.getBoundingClientRect();
    const px = (clientX - rect.left) / rect.width;
    const py = (clientY - rect.top) / rect.height;

    const nw = w / factor;
    const nh = h / factor;
    x = x + (w - nw) * px;
    y = y + (h - nh) * py;
    w = nw; h = nh;
    setVB();
  }

  function zoomCenter(factor) {
    const r = viewport.getBoundingClientRect();
    zoom(factor, r.left + r.width / 2, r.top + r.height / 2);
  }

  function reset() { x = x0; y = y0; w = w0; h = h0; setVB(); }

  // Buttons
  const zIn = wrap.querySelector('[data-svg-zoom-in]');
  const zOut = wrap.querySelector('[data-svg-zoom-out]');
  const zReset = wrap.querySelector('[data-svg-reset]');
  if (zIn) zIn.addEventListener('click', () => zoomCenter(1.25));
  if (zOut) zOut.addEventListener('click', () => zoomCenter(1 / 1.25));
  if (zReset) zReset.addEventListener('click', reset);

  // Drag-to-pan
  let dragging = false;
  let sx = 0, sy = 0, vx = 0, vy = 0;
  viewport.addEventListener('pointerdown', (e) => {
    dragging = true;
    viewport.classList.add('dragging');
    viewport.setPointerCapture(e.pointerId);
    sx = e.clientX; sy = e.clientY;
    vx = x; vy = y;
  });
  viewport.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const rect = viewport.getBoundingClientRect();
    const dx = (e.clientX - sx) * (w / rect.width);
    const dy = (e.clientY - sy) * (h / rect.height);
    x = vx - dx;
    y = vy - dy;
    setVB();
  });
  function stopDrag() { dragging = false; viewport.classList.remove('dragging'); }
  viewport.addEventListener('pointerup', stopDrag);
  viewport.addEventListener('pointercancel', stopDrag);

  // Wheel zoom
  viewport.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.25 : (1 / 1.25);
    zoom(factor, e.clientX, e.clientY);
  }, { passive: false });

  // Click outside nodes to clear highlight.
  viewport.addEventListener('click', () => {
    const nodes = svg.querySelectorAll('g.node');
    nodes.forEach((n) => n.classList.remove('selected'));
  });

  wrap.dataset.svgInited = '1';
}

function __svgInitAll() {
  document.querySelectorAll(".svgWrap[data-svgviewer='1']").forEach(__svgInitOne);
}


// ── Cytoscape CFG viewer (DOT -> graphlib-dot -> cytoscape) ────────────────

function __cyCleanLabel(s) {
  if (!s) return "";
  if (typeof s !== "string") s = "" + s;
  // Strip surrounding quotes
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
    s = s.slice(1, -1);
  }
  // Common Graphviz escapes
  // In DOT labels, "\\l" and "\\n" encode newlines.
  // Use string escapes ("\n") here; do NOT embed literal line breaks.
  s = s.replace(/\\l/g, "\n").replace(/\\n/g, "\n");
// If HTML-ish label, don't dump tags into canvas.
  if (s.startsWith("<") && (s.includes("TABLE") || s.includes("<TR") || s.includes("<TD"))) {
    return "(html label)";
  }
  return s;
}

function __cyUnquote(s) {
  if (!s) return "";
  s = "" + s;
  if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') return s.slice(1, -1);
  return s;
}

function __cySanColor(c) {
  c = __cyUnquote(c).trim();
  if (!c || c === "none") return "";
  // Already-valid CSS forms
  if (c[0] === "#" || c.startsWith("rgb") || c.startsWith("hsl")) return c;

  // Graphviz 'grayNN' / 'greyNN' (0..100)
  let gm = c.match(/^(gray|grey)(\d{1,3})$/i);
  if (gm) {
    let pct = parseInt(gm[2], 10);
    if (isNaN(pct)) pct = 50;
    pct = Math.max(0, Math.min(100, pct));
    const v = Math.round((pct / 100) * 255);
    return `rgb(${v},${v},${v})`;
  }

  // Graphviz X11 variants like deepskyblue4 -> deepskyblue
  const base = c.replace(/\d+$/, "");
  try {
    if (window.CSS && CSS.supports) {
      if (CSS.supports("color", c)) return c;
      if (base && CSS.supports("color", base)) return base;
    }
  } catch (e) {}

  // Fallback: return empty so caller uses defaults
  return "";
}


function __cyInitOne(wrap) {
  if (!wrap || wrap.dataset.cyInited === '1') return;

  const id = wrap.getAttribute('data-cyid') || "";
  const container = document.getElementById(id);
  const dot = (window.__CY_DOTS && window.__CY_DOTS[id]) ? window.__CY_DOTS[id] : "";

  if (!container) return;

  if (!window.cytoscape || !window.graphlibDot || !dot) {
    container.innerHTML = "<div class='muted'>Cytoscape viewer unavailable (missing libs or DOT).</div>";
    wrap.dataset.cyInited = '1';
    return;
  }

  let g = null;
  try {
    g = graphlibDot.read(dot);
  } catch (e) {
    container.innerHTML = "<div class='muted'>Failed to parse DOT.</div>";
    wrap.dataset.cyInited = '1';
    return;
  }

  const elements = [];

  const __isDark = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? true : false;
  const __nodeTxt = __isDark ? 'rgba(255,255,255,0.92)' : 'rgba(0,0,0,0.85)';
  const __nodeOutline = __isDark ? 'rgba(0,0,0,0.72)' : 'rgba(255,255,255,0.90)';
  const __fillDefault = __isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  const __borderDefault = __isDark ? 'rgba(255,255,255,0.35)' : 'rgba(0,0,0,0.40)';
  const __edgeTxt = __isDark ? 'rgba(255,255,255,0.82)' : 'rgba(0,0,0,0.60)';
  const __edgeTxtBg = __isDark ? 'rgba(0,0,0,0.55)' : 'rgba(255,255,255,0.85)';


  const nodes = g.nodes ? g.nodes() : [];
  nodes.forEach((nid) => {
    const a = (g.node && g.node(nid)) ? g.node(nid) : {};
    const label = __cyCleanLabel(a.label || a.lbl || nid);
    const tooltip = __cyCleanLabel(a.tooltip || a.title || "");
    const fill = __cySanColor(a.fillcolor || a.fill || "");
    const border = __cySanColor(a.color || "");
    const penwidth = parseFloat(a.penwidth || "1") || 1;
    const shape = __cyUnquote(a.shape || "");
    elements.push({
      data: { id: nid, label, tooltip, fill, border, penwidth, shape, raw: a, fillDefault: __fillDefault, borderDefault: __borderDefault, txt: __nodeTxt, txtOutline: __nodeOutline }
    });
  });

  const edges = g.edges ? g.edges() : [];
  edges.forEach((e, idx) => {
    const a = (g.edge && g.edge(e)) ? g.edge(e) : {};
    const color = __cySanColor(a.color || "");
    const penwidth = parseFloat(a.penwidth || "1") || 1;
    const label = __cyCleanLabel(a.label || "");
    const eid = e.name ? `e_${e.v}_${e.w}_${e.name}` : `e_${e.v}_${e.w}_${idx}`;
    elements.push({
      data: { id: eid, source: e.v, target: e.w, label, color, penwidth, raw: a, edgeTxt: __edgeTxt, edgeTxtBg: __edgeTxtBg }
    });
  });

  const style = [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'text-wrap': 'wrap',
        'text-max-width': 220,
        'font-size': 10,
        'color': (ele) => ele.data('txt') || 'rgba(0,0,0,0.85)',
        'text-outline-width': 1,
        'text-outline-color': (ele) => ele.data('txtOutline') || 'rgba(255,255,255,0.85)',
        'background-color': (ele) => ele.data('fill') || ele.data('fillDefault') || 'rgba(0,0,0,0.05)',
        'border-color': (ele) => ele.data('border') || ele.data('borderDefault') || 'rgba(0,0,0,0.4)',
        'border-width': (ele) => ele.data('penwidth') || 1,
        'shape': (ele) => {
          const s = (ele.data('shape') || '').toLowerCase();
          if (s === 'box' || s === 'rectangle') return 'roundrectangle';
          if (s === 'diamond') return 'diamond';
          if (s === 'ellipse' || s === 'circle') return 'ellipse';
          return 'roundrectangle';
        }
      }
    },
    {
      selector: 'edge',
      style: {
        'curve-style': 'bezier',
        'target-arrow-shape': 'triangle',
        'line-color': (ele) => ele.data('color') || 'rgba(0,0,0,0.35)',
        'target-arrow-color': (ele) => ele.data('color') || 'rgba(0,0,0,0.35)',
        'width': (ele) => ele.data('penwidth') || 1,
        'label': 'data(label)',
        'font-size': 9,
        'color': (ele) => ele.data('edgeTxt') || 'rgba(0,0,0,0.60)',
        'text-rotation': 'autorotate',
        'text-background-opacity': 1,
        'text-background-padding': 2,
        'text-background-color': (ele) => ele.data('edgeTxtBg') || 'rgba(255,255,255,0.85)'
      }
    },
    { selector: '.faded', style: { 'opacity': 0.12 } },
    { selector: '.sel', style: { 'border-width': 3, 'border-color': '#1d4ed8' } },
    { selector: 'edge.sel', style: { 'width': 3, 'line-color': '#1d4ed8', 'target-arrow-color': '#1d4ed8' } },
  ];

  let cy = null;
  try {
    cy = cytoscape({
      container: container,
      elements: elements,
      style: style,
      layout: { name: 'dagre', rankDir: 'TB', nodeSep: 25, edgeSep: 10, rankSep: 40 },
      minZoom: 0.08,
      maxZoom: 3.5,
      textureOnViewport: true,
      motionBlur: true,
    });
  } catch (e) {
    container.innerHTML = "<div class='muted'>Failed to init Cytoscape.</div>";
    wrap.dataset.cyInited = '1';
    return;
  }

  // Tools
  const sel = wrap.querySelector('[data-cy-layout]');
  const btnLayout = wrap.querySelector('[data-cy-run-layout]');
  const btnFit = wrap.querySelector('[data-cy-fit]');
  const btnClear = wrap.querySelector('[data-cy-clear]');
  const search = wrap.querySelector('[data-cy-search]');

  function runLayout() {
    const name = (sel && sel.value) ? sel.value : 'dagre';
    const opts = { name: name };
    if (name === 'dagre') {
      opts.rankDir = 'TB';
      opts.nodeSep = 25; opts.edgeSep = 10; opts.rankSep = 40;
    }
    cy.layout(opts).run();
  }

  if (btnLayout) btnLayout.addEventListener('click', () => runLayout());
  if (btnFit) btnFit.addEventListener('click', () => cy.fit(undefined, 20));
  if (btnClear) btnClear.addEventListener('click', () => {
    cy.elements().removeClass('faded sel');
    if (search) search.value = '';
  });

  // Search
  if (search) {
    search.addEventListener('input', () => {
      const q = (search.value || '').trim().toLowerCase();
      if (!q) {
        cy.elements().removeClass('faded sel');
        return;
      }

      cy.elements().addClass('faded').removeClass('sel');

      cy.nodes().forEach((n) => {
        const lbl = (n.data('label') || '').toLowerCase();
        const ok = lbl.includes(q) || n.id().toLowerCase().includes(q);
        if (ok) {
          n.removeClass('faded').addClass('sel');
          n.closedNeighborhood().removeClass('faded');
        }
      });
    });
  }

  function showNode(n) {
    if (!n) return;
    const tip = n.data('tooltip') || '';
    const raw = n.data('raw') || {};
    const body = tip ? tip : JSON.stringify(raw, null, 2);
    const label = n.data('label') || '';
    __bbInspectorOpen(n.id(), label, body);
  }

  function focusNode(n) {
    cy.elements().addClass('faded').removeClass('sel');
    n.removeClass('faded').addClass('sel');
    const nb = n.closedNeighborhood();
    nb.removeClass('faded');
    nb.addClass('sel');
  }

  cy.on('tap', 'node', (evt) => {
    const n = evt.target;
    focusNode(n);
    showNode(n);
  });

  cy.on('tap', 'edge', (evt) => {
    const e = evt.target;
    cy.elements().addClass('faded').removeClass('sel');
    e.removeClass('faded').addClass('sel');
  });

  cy.on('tap', (evt) => {
    if (evt.target === cy) {
      cy.elements().removeClass('faded sel');
    }
  });

  wrap.dataset.cyInited = '1';
}

function __cyInitAll() {
  document.querySelectorAll(".cyWrap[data-cyviewer='1']").forEach(__cyInitOne);
}

function __cyObserve() {
  const wraps = document.querySelectorAll(".cyWrap[data-cyviewer='1']");
  if (!wraps || !wraps.length) return;
  if (!('IntersectionObserver' in window)) {
    wraps.forEach(__cyInitOne);
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((ent) => {
      if (ent.isIntersecting) {
        __cyInitOne(ent.target);
      }
    });
  }, { root: null, rootMargin: '220px', threshold: 0.01 });
  wraps.forEach((w) => io.observe(w));
}


window.addEventListener('DOMContentLoaded', () => {
  __svgInitAll();
  try { __cyObserve(); } catch (e) { try { __cyInitAll(); } catch (e2) {} }

  // WASM renderer may insert SVG after DOMContentLoaded. Avoid running this hot:
  // debounce + only enable for wasm renderer.
  if (__OBF_RENDERER === 'wasm') {
    let __obsTimer = 0;
    const __kick = () => {
      if (__obsTimer) return;
      __obsTimer = window.setTimeout(() => {
        __obsTimer = 0;
        __svgInitAll();
      }, 80);
    };
    const obs = new MutationObserver(__kick);
    obs.observe(document.body, { childList: true, subtree: true });
  }

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') __bbInspectorClose();
  });
});
"""

    wasm_dots: Dict[str, str] = {}
    wasm_id = 0
    cy_dots: Dict[str, str] = {}
    cy_id = 0
    parts: List[str] = []

    parts.append("<!doctype html><html><head><meta charset='utf-8'>")
    parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    parts.append("<title>llvm_obfuscator report</title>")
    parts.append(f"<style>{css}</style>")
    js_rendered = js.replace("__RENDERER__", renderer)
    parts.append(f"<script>{js_rendered}</script>")
    parts.append("</head><body>")

    parts.append("<header>")
    parts.append("<h1>llvm_obfuscator — Obfuscation Report</h1>")
    parts.append(
        "<div class='meta'>"
        f"schema={_safe(schema)} v={_safe(version)} — "
        f"module={_safe(module.get('identifier',''))}"
        "</div>"
    )
    parts.append("</header>")

    parts.append("<main>")
    parts.append("<div class='controls'>")
    parts.append("<input id='search' type='search' placeholder='Filter functions…' oninput='filterFunctions()'>")
    parts.append(f"<span class='badge'>functions: {_safe(total)}</span>")
    parts.append(f"<span class='badge'>skipped: {_safe(skipped)}</span>")
    parts.append(
        "<span class='muted'>CFG coloring: new blocks = green, changed = yellow, obf-marked blocks = blue border.</span>"
    )

    if cyto_mode:
        parts.append("<span class='badge'>CFG renderer: Cytoscape.js (interactive)</span>")
        parts.append("<span class='muted'>Drag nodes, scroll to zoom, switch layouts, click nodes for the BB inspector.</span>")
    elif dot_mode:
        parts.append("<span class='badge'>CFG renderer: dot (server-side SVG)</span>")
    elif wasm_mode:
        parts.append("<span class='badge'>CFG renderer: d3-graphviz (Graphviz WASM)</span>")
        parts.append("<span class='muted'>If offline, install Graphviz (dot) or vendor the JS libs locally.</span>")
    else:
        parts.append("<span class='badge'>CFG renderer: text (DOT)</span>")

    parts.append("</div>")

    for f in functions:
        if not isinstance(f, dict):
            continue
        name = str(f.get("name", ""))
        insts = f.get("insts", {}) if isinstance(f.get("insts"), dict) else {}
        before = insts.get("before")
        after = insts.get("after")

        budget = f.get("budget", {}) if isinstance(f.get("budget"), dict) else {}
        budget_enabled = bool(budget.get("enabled"))
        budget_util = budget.get("utilization") if budget_enabled else None

        diff = f.get("difficulty", {}) if isinstance(f.get("difficulty"), dict) else {}
        try:
            score = float(diff.get("score", 0.0) or 0.0)
        except Exception:
            score = 0.0

        skipped_flag = bool(f.get("skipped"))
        skip_reason = str(f.get("skip_reason", "")) if skipped_flag else ""

        parts.append(f"<section class='card fnCard' data-name='{_safe(name)}'>")
        parts.append("<h2>")
        parts.append(f"<span>{_safe(name)}</span>")
        parts.append(f"<span class='pill'>difficulty: {_safe(f'{score:.1f}')}</span>")
        if skipped_flag:
            parts.append(f"<span class='pill'>skipped: {_safe(skip_reason)}</span>")
        parts.append("</h2>")

        parts.append("<div class='row'>")
        parts.append(
            f"<span class='kv'><span class='k'>insts</span><span class='v'>{_safe(before)} → {_safe(after)}</span></span>"
        )
        if budget_enabled:
            parts.append(
                f"<span class='kv'><span class='k'>budget</span><span class='v'>{_safe(budget.get('limit',''))}</span></span>"
            )
            parts.append(
                f"<span class='kv'><span class='k'>util</span><span class='v'>{_budget_bar(budget_util)}</span></span>"
            )
        parts.append("</div>")

        parts.append("<details>")
        parts.append("<summary class='muted'>details</summary>")

        seed = f.get("seed", {}) if isinstance(f.get("seed"), dict) else {}
        parts.append("<div class='row' style='margin-top:10px'>")
        parts.append(
            f"<span class='kv'><span class='k'>seed.base</span><span class='v'>{_safe(seed.get('base',''))}</span></span>"
            f"<span class='kv'><span class='k'>seed.module</span><span class='v'>{_safe(seed.get('module',''))}</span></span>"
            f"<span class='kv'><span class='k'>seed.function</span><span class='v'>{_safe(seed.get('function',''))}</span></span>"
        )
        parts.append("</div>")

        parts.append("<div class='pills' style='margin-top:10px'>")
        parts.append(
            f"<span class='pill'>cyclomatic: {_safe(diff.get('cyclomatic_before',''))} → {_safe(diff.get('cyclomatic_after',''))} (Δ{_safe(diff.get('cyclomatic_delta',''))})</span>"
        )
        try:
            opaque_val = float(diff.get("opaque_per_100_insts", 0.0) or 0.0)
        except Exception:
            opaque_val = 0.0
        parts.append(f"<span class='pill'>opaque/100 insts: {_safe('{:.2f}'.format(opaque_val))}</span>")
        parts.append(f"<span class='pill'>MBA max depth: {_safe(diff.get('mba_max_depth',''))}</span>")
        parts.append(f"<span class='pill'>indirect br: {_safe(diff.get('indirect_branches',''))}</span>")
        parts.append("</div>")

        passes = f.get("passes", [])
        if isinstance(passes, list) and passes:
            parts.append("<hr>")
            parts.append("<div class='muted'>passes</div>")
            parts.append("<table class='table'>")
            parts.append(
                "<thead><tr><th>id</th><th>status</th><th>changed</th><th>insts</th><th>Δ</th><th>budget util</th></tr></thead>"
            )
            parts.append("<tbody>")
            for p in passes:
                if not isinstance(p, dict):
                    continue
                status = p.get("status", "")
                changed = p.get("changed", "") if status == "ran" else ""
                insts_b = p.get("insts_before", "")
                insts_a = p.get("insts_after", "")
                delta = p.get("delta_insts", "")
                bu = p.get("budget_util_after", None)
                parts.append(
                    "<tr>"
                    f"<td><span class='v'>{_safe(p.get('id',''))}</span></td>"
                    f"<td>{_safe(status)}</td>"
                    f"<td>{_safe(changed)}</td>"
                    f"<td class='v'>{_safe(insts_b)} → {_safe(insts_a)}</td>"
                    f"<td class='v'>{_safe(delta)}</td>"
                    f"<td>{_budget_bar(bu if isinstance(bu,(int,float)) else None)}</td>"
                    "</tr>"
                )
            parts.append("</tbody></table>")

        artifacts = f.get("artifacts", {}) if isinstance(f.get("artifacts"), dict) else {}
        cfg = artifacts.get("cfg", {}) if isinstance(artifacts.get("cfg"), dict) else {}
        before_dot = str(cfg.get("before_dot", ""))
        after_dot = str(cfg.get("after_dot", ""))
        per_pass = cfg.get("per_pass", [])

        if before_dot or after_dot:
            parts.append("<hr>")
            parts.append("<div class='muted'>CFG snapshots</div>")
            parts.append("<div class='grid2'>")

            for title, rel in [("before", before_dot), ("after", after_dot)]:
                kind, payload = _load_dot_or_svg(report_dir, rel, dot_exe if dot_mode else None)
                parts.append("<div>")
                parts.append(f"<div class='muted'>{_safe(title)} — {_safe(rel)}</div>")
                if kind == "svg":
                    parts.append(_svg_viewer(payload, rel))
                elif kind == "dot":
                    if cyto_mode and rel.lower().endswith(".dot"):
                        dom_id = f"cy_{cy_id}"; cy_id += 1
                        cy_dots[dom_id] = payload
                        parts.append(_cy_viewer(dom_id, rel))
                        parts.append(f"<details><summary class='muted'>DOT source</summary><pre>{_safe(payload)}</pre></details>")
                    elif wasm_mode:
                        dom_id = f"gv_{wasm_id}"; wasm_id += 1
                        wasm_dots[dom_id] = payload
                        parts.append(_svg_viewer(f"<div id='{dom_id}' class='gv'></div>", rel))
                        parts.append(f"<details><summary class='muted'>DOT source</summary><pre>{_safe(payload)}</pre></details>")
                    else:
                        parts.append(f"<pre>{_safe(payload)}</pre>")
                else:
                    parts.append(f"<div class='muted'>{_safe(payload)}</div>")
                parts.append("</div>")

            parts.append("</div>")

        if isinstance(per_pass, list) and per_pass:
            parts.append("<hr>")
            parts.append("<div class='muted'>CFG per-pass diffs</div>")
            for stage in per_pass:
                if not isinstance(stage, dict):
                    continue
                p_name = str(stage.get("pass", ""))
                rel = str(stage.get("diff_dot", stage.get("after_dot", "")))
                kind, payload = _load_dot_or_svg(report_dir, rel, dot_exe if dot_mode else None)

                parts.append("<details style='margin-top:10px'>")
                parts.append(
                    f"<summary><span class='v'>{_safe(p_name)}</span> <span class='muted'>({_safe(rel)})</span></summary>"
                )
                if kind == "svg":
                    parts.append(_svg_viewer(payload, rel, extra_style="margin-top:10px"))
                elif kind == "dot":
                    if cyto_mode and rel.lower().endswith(".dot"):
                        dom_id = f"cy_{cy_id}"; cy_id += 1
                        cy_dots[dom_id] = payload
                        parts.append(_cy_viewer(dom_id, rel, extra_style="margin-top:10px"))
                        parts.append(f"<details><summary class='muted'>DOT source</summary><pre style='margin-top:10px'>{_safe(payload)}</pre></details>")
                    elif wasm_mode:
                        dom_id = f"gv_{wasm_id}"; wasm_id += 1
                        wasm_dots[dom_id] = payload
                        parts.append(_svg_viewer(f"<div id='{dom_id}' class='gv'></div>", rel, extra_style="margin-top:10px"))
                        parts.append(f"<details><summary class='muted'>DOT source</summary><pre style='margin-top:10px'>{_safe(payload)}</pre></details>")
                    else:
                        parts.append(f"<pre style='margin-top:10px'>{_safe(payload)}</pre>")
                else:
                    parts.append(f"<div class='muted' style='margin-top:10px'>{_safe(payload)}</div>")
                parts.append("</details>")

        parts.append("</details>")
        parts.append("</section>")

    # BB inspector UI
    parts.append(
        "<aside id='bbInspector' aria-label='Basic block inspector'>"
        "  <div class='hdr'>"
        "    <div class='title'><b>Basic block</b><span id='bbInspectorId' class='v'></span></div>"
        "    <button type='button' onclick='__bbInspectorClose()' title='Close'>×</button>"
        "  </div>"
        "  <div class='body'>"
        "    <div id='bbInspectorLabel' class='muted'></div>"
        "    <pre id='bbInspectorBody'></pre>"
        "  </div>"
        "</aside>"
    )

    if cyto_mode and cy_dots:
        # Cytoscape interactive CFG viewer (DOT -> graphlib -> cytoscape)
        parts.append("<script src='https://unpkg.com/cytoscape@3.33.1/dist/cytoscape.min.js'></script>")
        parts.append("<script src='https://cdnjs.cloudflare.com/ajax/libs/dagre/0.8.5/dagre.min.js'></script>")
        parts.append("<script src='https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js'></script>")
        parts.append("<script src='https://unpkg.com/graphlib-dot@0.6.4/dist/graphlib-dot.min.js'></script>")
        parts.append("<script>")
        parts.append("const __CY_DOTS = " + _json.dumps(cy_dots) + ";")
        parts.append("window.__CY_DOTS = __CY_DOTS;")
        parts.append(
            "try {"
            "  if (window.cytoscape) {"
            "    if (window.cytoscapeDagre) cytoscape.use(window.cytoscapeDagre);"
            "    if (window.cytoscapeDagre && window.cytoscapeDagre.default) cytoscape.use(window.cytoscapeDagre.default);"
            "  }"
            "} catch (e) {}"
        )
        parts.append(
            "window.addEventListener('DOMContentLoaded', () => {"
            "  try { __cyInitAll(); } catch (e) { console.warn('cy init failed', e); }"
            "});"
        )
        parts.append("</script>")


    if wasm_mode and wasm_dots:
        parts.append("<script src='https://d3js.org/d3.v7.min.js'></script>")
        parts.append("<script src='https://unpkg.com/@hpcc-js/wasm@2.20.0/dist/graphviz.umd.js'></script>")
        parts.append("<script src='https://unpkg.com/d3-graphviz@5.2.0/build/d3-graphviz.min.js'></script>")
        parts.append("<script>")
        parts.append("const __DOTS = " + _json.dumps(wasm_dots) + ";")
        parts.append(
            r"""
window.addEventListener('DOMContentLoaded', () => {
  for (const [id, dot] of Object.entries(__DOTS)) {
    try {
      // Render DOT to SVG; our global MutationObserver will enable pan/zoom + click hooks.
      d3.select('#' + id).graphviz().renderDot(dot);
    } catch (e) {
      console.warn('graphviz render failed for', id, e);
    }
  }
});
"""
        )
        parts.append("</script>")

    parts.append("</main></body></html>")
    return "".join(parts)


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate HTML report from llvm_obfuscator JSON.")
    ap.add_argument("--json", required=True, type=Path, help="Path to obf_report.json")
    ap.add_argument(
        "--report-dir",
        type=Path,
        default=None,
        help="Base directory for artifact paths (default: JSON directory)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output HTML path (default: <json_dir>/obf_report.html)",
    )
    ap.add_argument(
        "--renderer",
        type=str,
        default="auto",
        help="auto|cyto|dot|wasm|text (auto: cyto when DOT exists; else dot if available; else wasm)",
    )

    args = ap.parse_args(argv)

    data = _read_json(args.json)
    report_dir = args.report_dir if args.report_dir else args.json.parent
    out = args.out if args.out else (args.json.parent / "obf_report.html")

    doc = build_html(data, report_dir, args.renderer)
    out.write_text(doc, encoding="utf-8", newline="\n")
    print(f"wrote: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
