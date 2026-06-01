#!/usr/bin/env python3
"""WP-057 HTML renderer — Comprehensive Master Blueprint 2026-2030."""
import json
from pathlib import Path
from html import escape

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "comprehensive-master-blueprint.json"
OUT = ROOT / "public" / "comprehensive-master-blueprint.html"
OUT.parent.mkdir(parents=True, exist_ok=True)
DOC = json.loads(SRC.read_text())


def e(x):
    return escape(str(x))


def kv_pairs(d, skip=("mid", "sid", "title", "pid", "cid", "wid", "did", "gid", "rid", "qid", "tid", "aid", "fid", "vid", "bid", "name", "layer", "component", "system", "area", "category", "mechanism", "riskClass", "control", "phase", "milestone", "regime", "clause", "blueprint", "framework", "theme", "track", "scope")):
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


distinctive = [
    ("architectureRefs", "architecture-refs", "Reference Architecture Components"),
    ("complianceMaps", "compliance-maps", "Compliance Clause Mappings"),
    ("governanceFrameworks", "governance-frameworks", "Institutional Governance Frameworks"),
    ("safetyMechanisms", "safety-mechanisms", "Frontier Safety & Containment Mechanisms"),
    ("financialServicesRisks", "financial-services-risks", "Financial-Services Risk Controls"),
    ("civilizationalStacks", "civilizational-stacks", "Civilizational Governance Stacks"),
    ("roadmapItems", "roadmap-items", "Roadmap Items (RM-01..RM-15)"),
    ("regulatorBlueprints", "regulator-blueprints", "Regulator-Submission Blueprints"),
    ("researchTracks", "research-tracks", "Research Tracks (RT-01..RT-15)"),
]

label_keys_map = {
    "architectureRefs": ["aid", "system", "layer"],
    "complianceMaps": ["cid", "regime", "clause"],
    "governanceFrameworks": ["fid", "area", "framework"],
    "safetyMechanisms": ["sid", "category", "mechanism"],
    "financialServicesRisks": ["fid", "riskClass", "control"],
    "civilizationalStacks": ["vid", "layer", "mechanism"],
    "roadmapItems": ["rid", "phase", "milestone"],
    "regulatorBlueprints": ["bid", "regime", "blueprint"],
    "researchTracks": ["tid", "theme", "track"],
}

# TOC
toc_modules = "".join(f"<li><a href='#{e(m['mid'])}'>{e(m['mid'])} — {e(m['title'])}</a></li>" for m in DOC["modules"])
toc_distinct = "".join(f"<li><a href='#{anchor}'>{e(label)}</a></li>" for _, anchor, label in distinctive)

modules_html = "".join(module_html(m) for m in DOC["modules"])
distinctive_html = "".join(list_array(DOC[key], label_keys_map[key], anchor, label) for key, anchor, label in distinctive)


def table(rows, cols):
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body_rows = []
    for r in rows:
        tds = "".join(f"<td>{e(r.get(c, ''))}</td>" for c in cols)
        body_rows.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


tail_html = f"""
<section id='kpis'><h3>KPIs ({len(DOC['kpis'])})</h3>{table(DOC['kpis'], ['kid','name','target','cadence'])}</section>
<section id='rcm'><h3>Risk Control Matrix ({len(DOC['riskControlMatrix'])})</h3>{table(DOC['riskControlMatrix'], ['rid','risk','likelihood','impact','control','owner'])}</section>
<section id='trace'><h3>Cross-Jurisdictional Traceability ({len(DOC['traceability'])})</h3>{table(DOC['traceability'], ['tid','control','regime','clause','evidence'])}</section>
<section id='regulators'><h3>Regulators ({len(DOC['regulators'])})</h3>{table(DOC['regulators'], ['reg','scope','cadence'])}</section>
<section id='roadmap'><h3>Roadmap ({len(DOC['roadmap'])})</h3>{table(DOC['roadmap'], ['yr','milestone'])}</section>
<section id='evidence'><h3>Evidence Pack ({len(DOC['evidencePack'])})</h3>{table(DOC['evidencePack'], ['epid','name','format'])}</section>
"""

exs = DOC["executiveSummary"]
exec_html = f"""
<section id='exec'><h3>Executive Summary</h3>
<p><b>Headline:</b> {e(exs['headline'])}</p>
<p><b>Investment:</b> {e(exs['investment'])} · <b>NPV:</b> {e(exs['npv'])}</p>
<p><b>Phases:</b> {e(exs['phases'])}</p>
<p><b>Five-scope:</b> {', '.join(e(x) for x in exs['scopeFive'])}</p>
<p><b>Regimes:</b> {e(exs['regimes'])}</p>
<p><b>Top risks:</b> {', '.join(e(x) for x in exs['topRisks'])}</p>
<p><b>Top opportunities:</b> {', '.join(e(x) for x in exs['topOpportunities'])}</p>
<p><b>Board asks:</b> {', '.join(e(x) for x in exs['boardAsks'])}</p>
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
<ul>{toc_modules}</ul>
<h4>Distinctive Arrays</h4>
<ul>{toc_distinct}</ul>
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
print(f"WP-057 HTML written: {OUT}")
print(f"Size: {OUT.stat().st_size:,} bytes ({OUT.stat().st_size/1024:.1f} KB)")
