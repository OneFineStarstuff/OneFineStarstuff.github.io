#!/usr/bin/env python3
"""WP-056 HTML renderer — Prioritized Impl & Research Plan 2026-2030."""
import json
from pathlib import Path
from html import escape

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "prioritized-impl-research-plan.json"
OUT = ROOT / "public" / "prioritized-impl-research-plan.html"
OUT.parent.mkdir(parents=True, exist_ok=True)
DOC = json.loads(SRC.read_text())


def e(x):
    return escape(str(x))


def kv_pairs(d, skip=("mid", "sid", "title", "pid", "cid", "wid", "did", "gid", "rid", "qid", "tid", "name", "layer", "component", "area", "capability", "domain", "control", "scope", "regime", "artifact", "surface", "probe", "window", "predecessors")):
    """Render remaining dict fields as a list."""
    parts = []
    for k, v in d.items():
        if k in skip:
            continue
        if isinstance(v, list):
            inner = "".join(f"<li>{e(x) if not isinstance(x, dict) else e(json.dumps(x))}</li>" for x in v)
            parts.append(f"<div class='kv'><b>{e(k)}</b><ul>{inner}</ul></div>")
        elif isinstance(v, dict):
            inner = "".join(f"<li><b>{e(kk)}</b>: {e(vv)}</li>" for kk, vv in v.items())
            parts.append(f"<div class='kv'><b>{e(k)}</b><ul>{inner}</ul></div>")
        else:
            parts.append(f"<div class='kv'><b>{e(k)}</b>: {e(v)}</div>")
    return "".join(parts)


def section_html(s):
    body = kv_pairs(s)
    return f"<div class='sec'><h4>{e(s['sid'])}. {e(s['title'])}</h4>{body}</div>"


def module_html(m):
    secs = "".join(section_html(s) for s in m["sections"])
    return (
        f"<section class='module' id='{e(m['mid'])}'>"
        f"<h3>{e(m['mid'])} — {e(m['title'])}</h3>"
        f"<p class='sum'>{e(m['summary'])}</p>"
        f"{secs}</section>"
    )


def list_array(arr, label_keys, anchor, title):
    rows = []
    for it in arr:
        head_parts = [e(it.get(label_keys[0], ""))] + [e(it.get(k, "")) for k in label_keys[1:]]
        head = " · ".join(p for p in head_parts if p)
        body = kv_pairs(it)
        rows.append(f"<div class='card'><div class='card-head'>{head}</div>{body}</div>")
    return f"<section id='{anchor}'><h3>{title}</h3>{''.join(rows)}</section>"


# Build TOC
toc_items = []
for m in DOC["modules"]:
    toc_items.append(f"<li><a href='#{e(m['mid'])}'>{e(m['mid'])} — {e(m['title'])}</a></li>")
distinctive = [
    ("phases", "phases", "Phases (P0-P4)"),
    ("criticalPath", "critical-path", "Critical Path (CP-01..CP-13)"),
    ("sentinelStack", "sentinel-stack", "Sentinel v2.4 Stack"),
    ("workflowAIPro", "workflowai-pro", "WorkflowAI Pro Capabilities"),
    ("devSecOps", "devsecops", "DevSecOps Controls"),
    ("globalGovernance", "global-governance", "Global Governance Layers"),
    ("regulatorArtifacts", "regulator-artifacts", "Regulator Artifacts"),
    ("ragGovernance", "rag-governance", "RAG Governance Controls"),
    ("telemetryInterpretability", "telemetry-interp", "Telemetry & Interpretability Probes"),
]
for _key, anchor, label in distinctive:
    toc_items.append(f"<li><a href='#{anchor}'>{e(label)}</a></li>")

modules_html = "".join(module_html(m) for m in DOC["modules"])

# Distinctive arrays sections
label_keys_map = {
    "phases": ["pid", "name", "window"],
    "criticalPath": ["cid", "name"],
    "sentinelStack": ["sid", "layer", "component"],
    "workflowAIPro": ["wid", "area", "capability"],
    "devSecOps": ["did", "domain", "control"],
    "globalGovernance": ["gid", "layer", "scope"],
    "regulatorArtifacts": ["rid", "regime", "artifact"],
    "ragGovernance": ["qid", "area", "control"],
    "telemetryInterpretability": ["tid", "surface", "probe"],
}
distinctive_html = ""
for key, anchor, label in distinctive:
    distinctive_html += list_array(DOC[key], label_keys_map[key], anchor, label)

# Tail tables
def table(rows, cols):
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body_rows = []
    for r in rows:
        tds = "".join(f"<td>{e(r.get(c, ''))}</td>" for c in cols)
        body_rows.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


tail_html = f"""
<section id='kpis'><h3>KPIs ({len(DOC['kpis'])})</h3>{table(DOC['kpis'], ['kid','name','target','measurement'])}</section>
<section id='rcm'><h3>Risk Control Matrix ({len(DOC['riskControlMatrix'])})</h3>{table(DOC['riskControlMatrix'], ['rid','risk','likelihood','impact','control','owner'])}</section>
<section id='trace'><h3>Traceability ({len(DOC['traceability'])})</h3>{table(DOC['traceability'], ['tid','control','regime','clause','evidence'])}</section>
<section id='regulators'><h3>Regulators ({len(DOC['regulators'])})</h3>{table(DOC['regulators'], ['reg','scope','contactCadence'])}</section>
<section id='roadmap'><h3>Roadmap ({len(DOC['roadmap'])})</h3>{table(DOC['roadmap'], ['yr','milestone'])}</section>
<section id='evidence'><h3>Evidence Pack ({len(DOC['evidencePack'])})</h3>{table(DOC['evidencePack'], ['epid','name','format'])}</section>
"""

exec_summary = DOC["executiveSummary"]
exec_html = f"""
<section id='exec'><h3>Executive Summary</h3>
<p><b>Headline:</b> {e(exec_summary['headline'])}</p>
<p><b>Investment:</b> {e(exec_summary['investment'])} · <b>NPV:</b> {e(exec_summary['npv'])}</p>
<p><b>Phases:</b> {e(exec_summary['phases'])}</p>
<p><b>Top risks:</b> {', '.join(e(x) for x in exec_summary['topRisks'])}</p>
<p><b>Top opportunities:</b> {', '.join(e(x) for x in exec_summary['topOpportunities'])}</p>
<p><b>Board asks:</b> {', '.join(e(x) for x in exec_summary['boardAsks'])}</p>
</section>
"""

html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{e(DOC['title'])}</title>
<style>
:root {{ --bg:#0b0f14; --fg:#e6edf3; --muted:#9aa7b2; --acc:#58a6ff; --card:#11161d; --line:#23303d; }}
* {{ box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--fg); font-family:-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif; margin:0; line-height:1.5; }}
header {{ padding:24px 40px; border-bottom:1px solid var(--line); background:#0d1218; }}
header h1 {{ margin:0 0 4px 0; font-size:22px; }}
header .meta {{ color:var(--muted); font-size:13px; }}
.layout {{ display:grid; grid-template-columns:280px 1fr; gap:0; }}
nav.toc {{ border-right:1px solid var(--line); padding:20px; position:sticky; top:0; height:100vh; overflow-y:auto; background:#0d1218; }}
nav.toc h4 {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; margin:14px 0 6px; }}
nav.toc ul {{ list-style:none; padding:0; margin:0; }}
nav.toc li a {{ color:var(--fg); text-decoration:none; font-size:13px; display:block; padding:4px 6px; border-radius:4px; }}
nav.toc li a:hover {{ background:#1a232e; color:var(--acc); }}
main {{ padding:24px 40px; max-width:1200px; }}
section.module, section {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:18px 22px; margin-bottom:18px; }}
section h3 {{ margin-top:0; color:var(--acc); border-bottom:1px solid var(--line); padding-bottom:6px; }}
.sum {{ color:var(--muted); font-style:italic; }}
.sec {{ border-left:3px solid var(--acc); padding:6px 12px; margin:10px 0; background:#0e141b; border-radius:0 6px 6px 0; }}
.sec h4 {{ margin:4px 0 8px; color:#a5d6ff; font-size:14px; }}
.kv {{ font-size:13px; margin:4px 0; color:#d0d7de; }}
.kv b {{ color:#79c0ff; }}
.kv ul {{ margin:4px 0 4px 18px; padding:0; }}
.card {{ background:#0e141b; border:1px solid var(--line); border-radius:6px; padding:10px 12px; margin:8px 0; }}
.card-head {{ font-weight:600; color:#a5d6ff; margin-bottom:6px; font-size:13px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th, td {{ border:1px solid var(--line); padding:6px 8px; text-align:left; vertical-align:top; }}
th {{ background:#0e141b; color:var(--acc); }}
tr:nth-child(even) td {{ background:#0d131a; }}
.counts {{ display:flex; flex-wrap:wrap; gap:10px; margin:14px 0; }}
.counts span {{ background:#0e141b; border:1px solid var(--line); padding:4px 10px; border-radius:14px; font-size:12px; color:var(--muted); }}
.counts span b {{ color:var(--acc); }}
@media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; }} nav.toc {{ position:relative; height:auto; }} main {{ padding:20px; }} }}
</style>
</head><body>
<header>
<h1>{e(DOC['title'])}</h1>
<div class="meta">docRef <b>{e(DOC['docRef'])}</b> · v{e(DOC['version'])} · {e(DOC['status'])} · {e(DOC['classification'])} · generated {e(DOC['generatedAt'])}</div>
<div class="meta">Horizon: {e(DOC['horizon'])} · API prefix: <code>{e(DOC['apiPrefix'])}</code> · builds on {' · '.join(e(b) for b in DOC['buildsOn'])}</div>
<div class="counts">
{''.join(f"<span><b>{v}</b> {e(k)}</span>" for k,v in DOC['counts'].items())}
</div>
</header>
<div class="layout">
<nav class="toc">
<h4>Executive</h4>
<ul><li><a href='#exec'>Executive Summary</a></li></ul>
<h4>Modules (M1-M9)</h4>
<ul>{''.join(toc_items[:9])}</ul>
<h4>Distinctive Arrays</h4>
<ul>{''.join(toc_items[9:])}</ul>
<h4>Tail Tables</h4>
<ul>
<li><a href='#kpis'>KPIs</a></li>
<li><a href='#rcm'>Risk Control Matrix</a></li>
<li><a href='#trace'>Traceability</a></li>
<li><a href='#regulators'>Regulators</a></li>
<li><a href='#roadmap'>Roadmap</a></li>
<li><a href='#evidence'>Evidence Pack</a></li>
</ul>
</nav>
<main>
{exec_html}
{modules_html}
{distinctive_html}
{tail_html}
</main>
</div>
</body></html>
"""

OUT.write_text(html, encoding="utf-8")
print(f"WP-056 HTML written: {OUT}")
print(f"Size: {OUT.stat().st_size:,} bytes ({OUT.stat().st_size/1024:.1f} KB)")
