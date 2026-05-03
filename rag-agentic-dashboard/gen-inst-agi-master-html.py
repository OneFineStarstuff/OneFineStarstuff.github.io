#!/usr/bin/env python3
"""
WP-039 — HTML dashboard renderer for Institutional-Grade AGI/ASI & Enterprise AI
Governance Master Blueprint.

Reads data/inst-agi-master.json and writes public/inst-agi-master.html.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "inst-agi-master.json"
OUT = ROOT / "public" / "inst-agi-master.html"

MODULE_ORDER = [
    "M1_pillars", "M2_regulatory", "M3_architecture", "M4_workflowai",
    "M5_aims", "M6_creditUnderwriting", "M7_frontierSafety", "M8_globalLegal",
    "M9_commandCenter", "M10_supervisoryKpis", "M11_incident",
    "M12_querySimulation", "M13_maturityCodex", "M14_roadmap",
]


def esc(v):
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return html.escape(json.dumps(v, indent=2, ensure_ascii=False))
    return html.escape(str(v))


def render_value(v):
    if isinstance(v, list):
        if not v:
            return "<em>—</em>"
        if all(isinstance(x, str) for x in v):
            return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in v) + "</ul>"
        return "<ul>" + "".join(f"<li><pre class='inline'>{esc(x)}</pre></li>" for x in v) + "</ul>"
    if isinstance(v, dict):
        rows = "".join(f"<tr><th>{esc(k)}</th><td>{render_value(val)}</td></tr>"
                       for k, val in v.items())
        return f"<table class='kv'>{rows}</table>"
    return esc(v)


def render_section(s):
    sid = s.get("id", "")
    title = s.get("title", "")
    parts = [f"<div class='section' id='{esc(sid)}'>"
             f"<h4>{esc(sid)} — {esc(title)}</h4>"]
    for k, v in s.items():
        if k in ("id", "title"):
            continue
        parts.append(f"<div class='field'><div class='fk'>{esc(k)}</div>"
                     f"<div class='fv'>{render_value(v)}</div></div>")
    parts.append("</div>")
    return "".join(parts)


def render_module(m):
    mid = m.get("id", "")
    title = m.get("title", "")
    summary = m.get("summary", "")
    sections = m.get("sections", [])
    body = "".join(render_section(s) for s in sections)
    return (f"<section class='module' id='{esc(mid)}'>"
            f"<h2>{esc(title)}</h2>"
            f"<p class='summary'>{esc(summary)}</p>{body}</section>")


def main():
    data = json.loads(SRC.read_text())
    meta = data.get("meta", {})
    es = data.get("executiveSummary", {})

    n_modules = sum(1 for k in MODULE_ORDER if k in data)
    n_sections = sum(len(data[k].get("sections", [])) for k in MODULE_ORDER if k in data)
    n_schemas = len(data.get("schemas", {}))
    n_code = len(data.get("codeExamples", []))
    n_cases = len(data.get("caseStudies", []))
    n_routes = len(data.get("apiEndpoints", []))

    # TOC
    toc_items = "".join(
        f"<li><a href='#{esc(data[k]['id'])}'>{esc(data[k]['id'])} — "
        f"{esc(data[k]['title'].split(' — ', 1)[-1] if ' — ' in data[k]['title'] else data[k]['title'])}</a></li>"
        for k in MODULE_ORDER if k in data
    )

    # Modules
    modules_html = "".join(render_module(data[k]) for k in MODULE_ORDER if k in data)

    # Schemas
    schemas_html = "".join(
        f"<div class='card'><h4>{esc(name)}</h4>"
        f"<p>{esc(spec.get('title', ''))}</p>"
        f"<pre>{esc(spec.get('fields', []))}</pre></div>"
        for name, spec in data.get("schemas", {}).items()
    )

    # Code examples
    code_html = "".join(
        f"<tr><td>{esc(c.get('id'))}</td><td>{esc(c.get('title'))}</td>"
        f"<td>{esc(c.get('language'))}</td><td>{esc(c.get('lines'))}</td></tr>"
        for c in data.get("codeExamples", [])
    )

    # Case studies
    cases_html = "".join(
        f"<tr><td>{esc(c.get('id'))}</td><td>{esc(c.get('title'))}</td>"
        f"<td>{esc(c.get('outcome'))}</td></tr>"
        for c in data.get("caseStudies", [])
    )

    # API routes
    routes_html = "".join(f"<li><code>{esc(r)}</code></li>" for r in data.get("apiEndpoints", []))

    # Regulatory alignment
    reg_html = "".join(f"<li>{esc(r)}</li>" for r in meta.get("regulatoryAlignment", []))

    # Synthesizes
    synth_html = "".join(f"<li>{esc(r)}</li>" for r in meta.get("synthesizes", []))

    # Audience
    aud_html = "".join(f"<li>{esc(a)}</li>" for a in meta.get("audience", []))

    # Outcomes
    outcomes_html = "".join(f"<li>{esc(o)}</li>" for o in es.get("keyOutcomes", []))
    principles_html = "".join(f"<li>{esc(p)}</li>" for p in es.get("designPrinciples", []))

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(meta.get('docRef'))} — {esc(meta.get('title'))}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;background:#0b1220;color:#e8edf5;line-height:1.5}}
header{{background:linear-gradient(135deg,#0a2540 0%,#1a365d 100%);padding:32px 24px;border-bottom:3px solid #4f8af0}}
h1{{margin:0 0 8px 0;font-size:1.8rem}}
h2{{color:#7eb6ff;border-bottom:1px solid #2a3a5a;padding-bottom:6px;margin-top:32px}}
h3{{color:#b9d3ff}}
h4{{color:#c8dcff;margin:14px 0 6px 0}}
.container{{max-width:1280px;margin:0 auto;padding:24px}}
.badges{{margin-top:12px}}
.badge{{display:inline-block;background:#1a365d;color:#cfe0ff;padding:4px 10px;border-radius:14px;font-size:0.78rem;margin:3px 4px 0 0;border:1px solid #4f8af0}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:16px}}
.kpi-card{{background:#142037;border:1px solid #2a3a5a;border-radius:8px;padding:14px;text-align:center}}
.kpi-num{{font-size:1.6rem;font-weight:700;color:#7eb6ff}}
.kpi-label{{font-size:0.82rem;color:#a8b9d4;margin-top:4px}}
.toc{{background:#142037;border:1px solid #2a3a5a;padding:16px 20px;border-radius:8px;margin:16px 0}}
.toc ul{{margin:6px 0 0 0;padding-left:20px;columns:2}}
.toc a{{color:#7eb6ff;text-decoration:none}}
.toc a:hover{{text-decoration:underline}}
.module{{background:#0f1a2e;border:1px solid #2a3a5a;border-radius:10px;padding:20px;margin:18px 0}}
.section{{background:#142037;border-left:3px solid #4f8af0;border-radius:6px;padding:12px 14px;margin:10px 0}}
.summary{{font-style:italic;color:#a8b9d4}}
.field{{margin:8px 0}}
.fk{{font-weight:600;color:#b9d3ff;font-size:0.86rem;text-transform:uppercase;letter-spacing:0.3px}}
.fv{{margin-top:4px}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}
table.kv th{{text-align:left;background:#1a2944;color:#cfe0ff;font-weight:600;padding:6px 10px;border:1px solid #2a3a5a;width:30%;vertical-align:top}}
table.kv td{{padding:6px 10px;border:1px solid #2a3a5a;background:#0f1a2e;vertical-align:top}}
table.std{{margin-top:10px}}
table.std th, table.std td{{padding:8px 10px;border:1px solid #2a3a5a;text-align:left;background:#0f1a2e}}
table.std th{{background:#1a2944;color:#cfe0ff}}
ul{{margin:4px 0 4px 0;padding-left:20px}}
pre{{background:#0a1426;border:1px solid #2a3a5a;padding:8px;border-radius:6px;overflow:auto;font-size:0.82rem;color:#cfe0ff}}
pre.inline{{display:inline-block;padding:2px 6px;margin:0;font-size:0.8rem}}
code{{background:#0a1426;padding:1px 6px;border-radius:4px;color:#7eb6ff;font-size:0.82rem}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}}
.card{{background:#142037;border:1px solid #2a3a5a;border-radius:8px;padding:12px}}
.routes{{columns:2;list-style:none;padding-left:0}}
.routes li{{margin:2px 0;break-inside:avoid}}
footer{{text-align:center;padding:24px;color:#6b7a99;font-size:0.85rem;border-top:1px solid #2a3a5a;margin-top:32px}}
</style>
</head>
<body>
<header>
<div class="container">
  <h1>{esc(meta.get('title'))}</h1>
  <p style="color:#cfe0ff;margin:6px 0 0 0">{esc(meta.get('subtitle'))}</p>
  <div class="badges">
    <span class="badge">{esc(meta.get('docRef'))}</span>
    <span class="badge">v{esc(meta.get('version'))}</span>
    <span class="badge">{esc(meta.get('horizon'))}</span>
    <span class="badge">{esc(meta.get('classification'))}</span>
  </div>
  <div class="badges" style="margin-top:8px">
    <span class="badge">EU AI Act 2026</span>
    <span class="badge">NIST AI RMF 1.0</span>
    <span class="badge">ISO/IEC 42001</span>
    <span class="badge">GDPR</span>
    <span class="badge">SR 11-7</span>
    <span class="badge">Basel III/IV</span>
    <span class="badge">PRA / FCA / MAS / HKMA</span>
    <span class="badge">SLSA L3 + Sigstore</span>
  </div>
</div>
</header>

<div class="container">

<div class="kpi-grid">
  <div class="kpi-card"><div class="kpi-num">{n_modules}</div><div class="kpi-label">Modules</div></div>
  <div class="kpi-card"><div class="kpi-num">{n_sections}</div><div class="kpi-label">Sections</div></div>
  <div class="kpi-card"><div class="kpi-num">8</div><div class="kpi-label">Architectural Planes</div></div>
  <div class="kpi-card"><div class="kpi-num">320</div><div class="kpi-label">Controls</div></div>
  <div class="kpi-card"><div class="kpi-num">18</div><div class="kpi-label">KPIs</div></div>
  <div class="kpi-card"><div class="kpi-num">{n_schemas}</div><div class="kpi-label">JSON Schemas</div></div>
  <div class="kpi-card"><div class="kpi-num">{n_code}</div><div class="kpi-label">Code Examples</div></div>
  <div class="kpi-card"><div class="kpi-num">{n_cases}</div><div class="kpi-label">Case Studies</div></div>
  <div class="kpi-card"><div class="kpi-num">{n_routes}</div><div class="kpi-label">API Routes</div></div>
</div>

<h2>Executive Summary</h2>
<div class="card">
<h3>Purpose</h3>
<p>{esc(es.get('purpose'))}</p>
<h3>Scope</h3>
<p>{esc(es.get('scope'))}</p>
<h3>Design Principles</h3>
<ul>{principles_html}</ul>
<h3>Key Outcomes</h3>
<ul>{outcomes_html}</ul>
<h3>Board Narrative</h3>
<p>{esc(es.get('boardNarrative'))}</p>
</div>

<h2>Synthesizes (Workpackage Lineage)</h2>
<ul>{synth_html}</ul>

<h2>Document Metadata</h2>
<table class="kv">
  <tr><th>Owner</th><td>{esc(meta.get('owner'))}</td></tr>
  <tr><th>Audience</th><td><ul>{aud_html}</ul></td></tr>
  <tr><th>Subject System</th><td>{render_value(meta.get('subjectSystem') or {})}</td></tr>
  <tr><th>Deliverable Inventory</th><td>{render_value(meta.get('deliverableInventory') or {})}</td></tr>
</table>

<h2>Regulatory Alignment</h2>
<ul>{reg_html}</ul>

<h2>Table of Contents</h2>
<div class="toc"><ul>{toc_items}</ul></div>

{modules_html}

<h2>JSON Schemas ({n_schemas})</h2>
<div class="cards">{schemas_html}</div>

<h2>Code Examples ({n_code})</h2>
<table class="std">
<thead><tr><th>ID</th><th>Title</th><th>Language</th><th>Lines</th></tr></thead>
<tbody>{code_html}</tbody>
</table>

<h2>Case Studies ({n_cases})</h2>
<table class="std">
<thead><tr><th>ID</th><th>Title</th><th>Outcome</th></tr></thead>
<tbody>{cases_html}</tbody>
</table>

<h2>API Endpoints ({n_routes})</h2>
<ul class="routes">{routes_html}</ul>

<footer>
{esc(meta.get('docRef'))} v{esc(meta.get('version'))} · {esc(meta.get('horizon'))}<br>
Synthesizes WP-035 + WP-036 + WP-037 + WP-038
</footer>

</div>
</body>
</html>
"""

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page)
    size_kb = OUT.stat().st_size / 1024
    print(f"[OK] Generated {OUT} ({size_kb:.1f} KB)")
    print(f"     modules={n_modules} sections={n_sections} schemas={n_schemas} "
          f"code={n_code} cases={n_cases} routes={n_routes}")


if __name__ == "__main__":
    main()
