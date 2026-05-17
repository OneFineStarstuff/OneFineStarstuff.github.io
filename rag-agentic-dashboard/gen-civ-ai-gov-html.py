#!/usr/bin/env python3
"""Generate the WP-031 Civilizational AI Governance Stack HTML dashboard
from data/civ-ai-gov-stack.json."""

import json
import html
from pathlib import Path

HERE = Path(__file__).parent
DATA = json.load(open(HERE / "data" / "civ-ai-gov-stack.json"))
OUT  = HERE / "public" / "civ-ai-gov-stack.html"


def esc(s):
    if s is None:
        return ""
    return html.escape(str(s))


def render_list(items, cls=""):
    if not items:
        return ""
    return '<ul class="ul-tight' + (" " + cls if cls else "") + '">' + \
        "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>"


def render_kv_table(obj, headers=("Key", "Value")):
    if not obj:
        return ""
    # If obj is a list, fall back to render_list
    if isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            keys = list(obj[0].keys())[:5]
            return render_dict_list(obj, [(k, k.title()) for k in keys])
        return render_list([str(x) for x in obj])
    if not isinstance(obj, dict):
        return f"<p class='content'>{esc(str(obj))}</p>"
    rows = []
    for k, v in obj.items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = json.dumps(v, ensure_ascii=False)
        rows.append(f"<tr><td class='mn'>{esc(k)}</td><td>{esc(v)}</td></tr>")
    return f"""<div class="tc"><table>
<thead><tr><th>{esc(headers[0])}</th><th>{esc(headers[1])}</th></tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>"""


def render_dict_list(items, fields):
    """Render list of dicts as a table using given (key, label) tuples.
    Gracefully falls back to a bullet list if items are not all dicts."""
    if not items:
        return ""
    # If any item is not a dict, render as a simple bullet list
    if not all(isinstance(it, dict) for it in items):
        return render_list([str(it) if not isinstance(it, (dict, list)) else json.dumps(it, ensure_ascii=False)
                            for it in items])
    thead = "".join(f"<th>{esc(label)}</th>" for _, label in fields)
    rows = []
    for it in items:
        tds = []
        for k, _ in fields:
            v = it.get(k, "")
            if isinstance(v, list):
                v = "<br>".join(f"• {esc(x)}" if isinstance(x, str)
                                else f"• {esc(json.dumps(x, ensure_ascii=False))}"
                                for x in v)
                tds.append(f"<td>{v}</td>")
            elif isinstance(v, dict):
                tds.append(f"<td><code class='mn'>{esc(json.dumps(v, ensure_ascii=False))[:160]}</code></td>")
            else:
                tds.append(f"<td>{esc(v)}</td>")
        rows.append("<tr>" + "".join(tds) + "</tr>")
    return f"""<div class="tc"><table>
<thead><tr>{thead}</tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>"""


# ──────────────────────────────────────────────────────────────────────────────
# HEAD / STYLE (compact, inherits Tailwind-like tokens from ENT dashboard)
# ──────────────────────────────────────────────────────────────────────────────
meta = DATA["meta"]
doc_ref = meta["docRef"]
version = meta["version"]
horizon = meta.get("horizon", "2026-2050+")
classification = meta.get("classification", "CONFIDENTIAL")

HEAD = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(doc_ref)} — Civilizational AI Governance Stack 2026-2050+</title>
<meta name="description" content="Expert-level synthesis and analytical framework for a 2026-2050+ civilizational AI governance stack. Core principles, six-plane architecture, closing charge, regulator submission pack, kill-switch validation, systemic risk simulation, global interoperability & treaty framework, coalition activation, governance constitution & continuity codex, covenant codex canon, ratification ceremony, renewal atlas, stewardship roadmap, terminal governance attractor. Aligned with NIST AI RMF, ISO/IEC 42001, EU AI Act, GDPR, SR 11-7.">
<meta name="doc-ref" content="{esc(doc_ref)}">
<meta name="doc-version" content="{esc(version)}">
<meta name="classification" content="{esc(classification)}">
<style>
:root{{--bg:#07090f;--bg2:#0d1220;--card:#141b2e;--card-h:#1a2342;--t1:#e5e9f0;--t2:#94a3b8;--t3:#64748b;--blue:#3b82f6;--cyan:#06b6d4;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--pink:#ec4899;--indigo:#6366f1;--gold:#eab308;--b1:#1e293b;--b2:#334155;--mono:'Cascadia Code','Fira Code',monospace;--sans:'Inter',-apple-system,sans-serif;--r:12px;--rs:8px;--tr:all .3s cubic-bezier(.4,0,.2,1)}}
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
html{{scroll-behavior:smooth;font-size:15px}}
body{{font-family:var(--sans);background:var(--bg);color:var(--t1);line-height:1.6;overflow-x:hidden}}
a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}
.skip{{position:absolute;top:-100px;left:8px;background:var(--blue);color:#fff;padding:8px 16px;border-radius:6px;z-index:9999;font-size:.85rem}}.skip:focus{{top:8px}}
.hero{{background:linear-gradient(135deg,#0b0f24,#1b1240 48%,#0c0a20);padding:2rem 1.5rem 1.5rem;border-bottom:1px solid var(--b1);position:relative;overflow:hidden}}
.hero::before{{content:'';position:absolute;top:-50%;right:-20%;width:70%;height:200%;background:radial-gradient(ellipse,rgba(139,92,246,.08),transparent 70%);pointer-events:none}}
.hero-inner{{max-width:1600px;margin:0 auto;position:relative}}
.badge-doc{{display:inline-flex;align-items:center;gap:6px;background:rgba(139,92,246,.14);color:var(--purple);padding:4px 12px;border-radius:20px;font-size:.72rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;margin-bottom:.75rem;border:1px solid rgba(139,92,246,.25)}}
.hero h1{{font-size:1.75rem;font-weight:800;letter-spacing:-.02em;margin-bottom:.35rem;background:linear-gradient(135deg,#e2e8f0,#94a3b8 60%,#c4b5fd);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.hero-sub{{color:var(--t2);font-size:.85rem;max-width:1180px}}
.hero-meta{{display:flex;flex-wrap:wrap;gap:1.25rem;margin-top:1rem}}
.hero-meta-item{{display:flex;align-items:center;gap:6px;font-size:.72rem;color:var(--t3)}}.hero-meta-item strong{{color:var(--t2)}}
.live-badge{{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;background:rgba(16,185,129,.14);color:var(--green);border:1px solid rgba(16,185,129,.25)}}
.live-dot{{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pd 2s infinite}}@keyframes pd{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
.status-bar{{background:var(--bg2);border-bottom:1px solid var(--b1);padding:.5rem 1.5rem;display:flex;gap:1.5rem;flex-wrap:wrap;font-size:.7rem}}
.si{{display:flex;align-items:center;gap:5px;color:var(--t3)}}.si .v{{color:var(--cyan);font-weight:600;font-family:var(--mono)}}
nav.sn{{background:var(--bg2);border-bottom:1px solid var(--b1);padding:0 1.5rem;position:sticky;top:0;z-index:100;overflow-x:auto}}
nav.sn ul{{list-style:none;display:flex;max-width:1600px;margin:0 auto}}
nav.sn li a{{display:block;padding:.7rem .85rem;font-size:.7rem;font-weight:500;color:var(--t3);white-space:nowrap;border-bottom:2px solid transparent;transition:var(--tr)}}
nav.sn li a:hover{{color:var(--t1);background:rgba(139,92,246,.06);text-decoration:none}}
nav.sn li a.active{{color:var(--purple);border-bottom-color:var(--purple)}}
main{{max-width:1600px;margin:0 auto;padding:1.5rem}}
section{{margin-bottom:2.5rem;scroll-margin-top:60px}}
.sh{{display:flex;align-items:center;gap:10px;margin-bottom:1.1rem;padding-bottom:.75rem;border-bottom:1px solid var(--b1);flex-wrap:wrap}}
.sh h2{{font-size:1.2rem;font-weight:700}}
.sb{{display:inline-block;background:rgba(139,92,246,.1);color:var(--purple);padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;font-family:var(--mono)}}
.sd{{color:var(--t2);font-size:.83rem;margin-bottom:1rem;max-width:1150px;line-height:1.7}}
.g2{{display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:1rem}}
.g3{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem}}
.g4{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.85rem}}
.card{{background:linear-gradient(145deg,rgba(30,41,59,.55),rgba(15,23,42,.8));border:1px solid var(--b1);border-radius:var(--r);padding:1.1rem;transition:var(--tr);box-shadow:0 4px 24px rgba(0,0,0,.3)}}
.card:hover{{border-color:var(--b2);box-shadow:0 0 22px rgba(139,92,246,.18);transform:translateY(-1px)}}
.card h3{{font-size:.9rem;font-weight:700;margin-bottom:.4rem;color:var(--t1)}}
.card .code{{display:inline-block;font-family:var(--mono);font-size:.65rem;color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 6px;border-radius:3px;margin-bottom:.4rem}}
.card p{{font-size:.78rem;color:var(--t2);line-height:1.65;margin-bottom:.5rem}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:.75rem;margin-bottom:1.25rem}}
.kpi{{background:linear-gradient(145deg,rgba(30,41,59,.6),rgba(15,23,42,.85));border:1px solid var(--b1);border-radius:var(--rs);padding:.9rem;text-align:center;transition:var(--tr)}}
.kpi:hover{{border-color:var(--purple);box-shadow:0 0 20px rgba(139,92,246,.2)}}
.kv{{font-size:1.5rem;font-weight:800;font-family:var(--mono);background:linear-gradient(135deg,var(--cyan),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.kl{{font-size:.68rem;color:var(--t3);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.3px;font-family:var(--mono);margin:1px}}
.bg-blue{{background:rgba(59,130,246,.12);color:var(--blue)}}.bg-green{{background:rgba(16,185,129,.12);color:var(--green)}}
.bg-amber{{background:rgba(245,158,11,.12);color:var(--amber)}}.bg-red{{background:rgba(220,38,38,.12);color:var(--red)}}
.bg-purple{{background:rgba(139,92,246,.12);color:var(--purple)}}.bg-pink{{background:rgba(236,72,153,.12);color:var(--pink)}}
.bg-cyan{{background:rgba(6,182,212,.12);color:var(--cyan)}}.bg-indigo{{background:rgba(99,102,241,.12);color:var(--indigo)}}
.bg-gold{{background:rgba(234,179,8,.15);color:var(--gold)}}
.tc{{overflow-x:auto;border-radius:var(--rs);border:1px solid var(--b1);margin:.5rem 0}}
table{{width:100%;border-collapse:collapse;font-size:.77rem}}
thead{{background:rgba(15,23,42,.6)}}
th{{padding:.5rem .75rem;text-align:left;font-weight:600;color:var(--t2);font-size:.68rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--b1)}}
td{{padding:.5rem .75rem;border-bottom:1px solid var(--b1);color:var(--t1);vertical-align:top}}
tr:hover td{{background:rgba(139,92,246,.04)}}
.mn{{font-family:var(--mono);font-size:.72rem}}
.toc{{background:var(--card);border:1px solid var(--b1);border-radius:var(--r);padding:1.1rem;margin-bottom:1.5rem}}
.toc-title{{font-size:.85rem;font-weight:700;margin-bottom:.75rem;color:var(--t1)}}
.toc-list{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.25rem}}
.toc-list a{{display:flex;align-items:center;gap:6px;padding:4px 8px;font-size:.72rem;color:var(--t2);border-radius:4px;transition:var(--tr)}}
.toc-list a:hover{{background:rgba(139,92,246,.06);color:var(--purple);text-decoration:none}}
.toc-list .toc-num{{color:var(--cyan);font-family:var(--mono);font-weight:600;min-width:28px}}
.plane-card{{background:linear-gradient(145deg,rgba(139,92,246,.08),rgba(30,41,59,.6));border:1px solid rgba(139,92,246,.25);border-radius:var(--r);padding:1.1rem}}
.plane-card h3{{display:flex;align-items:center;gap:10px;font-size:.95rem;font-weight:700;margin-bottom:.5rem}}
.plane-num{{background:linear-gradient(135deg,var(--purple),var(--indigo));color:#fff;width:34px;height:34px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.85rem;font-family:var(--mono)}}
.ul-tight{{list-style:none;padding-left:0;font-size:.75rem;color:var(--t2);line-height:1.65}}
.ul-tight li{{padding:3px 0;padding-left:14px;position:relative}}
.ul-tight li::before{{content:'▸';position:absolute;left:0;color:var(--cyan)}}
pre.code{{background:#05070c;border:1px solid var(--b1);border-radius:var(--rs);padding:.9rem;overflow-x:auto;font-family:var(--mono);font-size:.72rem;color:#cbd5e1;line-height:1.55;margin:.5rem 0}}
.princ-card{{background:linear-gradient(145deg,rgba(6,182,212,.05),rgba(30,41,59,.55));border:1px solid rgba(6,182,212,.18);border-radius:var(--r);padding:1rem;transition:var(--tr)}}
.princ-card:hover{{border-color:var(--cyan);box-shadow:0 0 18px rgba(6,182,212,.15)}}
.princ-num{{display:inline-block;background:rgba(6,182,212,.15);color:var(--cyan);padding:1px 7px;border-radius:4px;font-family:var(--mono);font-size:.65rem;font-weight:700;margin-right:6px}}
.princ-name{{font-weight:700;font-size:.85rem;color:var(--t1)}}
.princ-stmt{{font-size:.78rem;color:var(--t2);margin:.4rem 0;line-height:1.65}}
.princ-cite{{font-size:.67rem;color:var(--t3);font-family:var(--mono)}}
.callout{{border-left:3px solid var(--purple);background:rgba(139,92,246,.05);padding:.8rem 1rem;border-radius:0 var(--rs) var(--rs) 0;margin:.5rem 0;font-size:.78rem;color:var(--t2);line-height:1.7}}
.callout.gold{{border-left-color:var(--gold);background:rgba(234,179,8,.05)}}
.callout.red{{border-left-color:var(--red);background:rgba(239,68,68,.05)}}
.callout.green{{border-left-color:var(--green);background:rgba(16,185,129,.05)}}
.callout strong{{color:var(--t1)}}
.section-inner{{padding:1rem;background:linear-gradient(145deg,rgba(30,41,59,.4),rgba(15,23,42,.65));border:1px solid var(--b1);border-radius:var(--r);margin-bottom:1rem}}
.section-inner h3{{font-size:.95rem;font-weight:700;color:var(--t1);margin-bottom:.4rem;display:flex;align-items:center;gap:10px}}
.section-inner .sid{{font-family:var(--mono);font-size:.65rem;color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 7px;border-radius:4px}}
.section-inner p.content{{font-size:.8rem;color:var(--t2);line-height:1.7;margin-bottom:.7rem}}
.footer{{border-top:1px solid var(--b1);padding:2rem 1.5rem;text-align:center;color:var(--t3);font-size:.72rem;margin-top:3rem;background:var(--bg2)}}
.footer a{{color:var(--purple)}}
@media(max-width:768px){{.hero h1{{font-size:1.35rem}}.g2,.g3{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<a href="#main" class="skip">Skip to content</a>
"""

# ──────────────────────────────────────────────────────────────────────────────
# HERO + STATUS + NAV
# ──────────────────────────────────────────────────────────────────────────────
hero_meta_items = "".join(f"<span class='hero-meta-item'>🔖 <strong>{esc(k)}:</strong> {esc(v)}</span>"
                          for k, v in [("Doc-Ref", doc_ref),
                                       ("Version", version),
                                       ("Date", meta.get("date", "")),
                                       ("Classification", classification),
                                       ("Horizon", horizon),
                                       ("Owner", meta.get("owner", "Civilizational AI Governance Council"))])

HERO = f"""
<div class="hero">
  <div class="hero-inner">
    <span class="badge-doc">◆ Institutional-Grade · Civilizational Horizon · Regulator-Defensible</span>
    <h1>Civilizational AI Governance Stack 2026-2050+</h1>
    <p class="hero-sub">End-to-end analytical framework integrating <strong>enterprise AI governance</strong> (2026-2030) with <strong>frontier AGI/ASI</strong> controls, global <strong>treaty-level interoperability</strong>, civilizational <strong>constitution &amp; covenant codex</strong>, and a <strong>terminal governance attractor</strong> aligning memory, meaning, action, and legitimacy under partial compliance. Aligned with NIST AI RMF, ISO/IEC 42001, EU AI Act, GDPR, SR 11-7 and sector model-risk standards.</p>
    <div class="hero-meta">{hero_meta_items}<span class="live-badge"><span class="live-dot"></span> Live API</span></div>
  </div>
</div>
<div class="status-bar">
  <span class="si">Modules: <span class="v">10</span></span>
  <span class="si">Indices: <span class="v">{len(DATA['indices'])}</span></span>
  <span class="si">Architecture Planes: <span class="v">{len(DATA['architecture']['planes'])}</span></span>
  <span class="si">Case Studies: <span class="v">{len(DATA['caseStudies'])}</span></span>
  <span class="si">Schemas: <span class="v">{len(DATA['schemas'])}</span></span>
  <span class="si">Code Examples: <span class="v">{len(DATA['codeExamples'])}</span></span>
  <span class="si">API Endpoints: <span class="v">72+</span></span>
  <span class="si">Regulatory Horizon: <span class="v">NIST · ISO · EU AI Act · GDPR · SR 11-7</span></span>
</div>
"""

# Navigation sections
nav_sections = [
    ("exec", "Executive Summary"),
    ("m1", "M1 · Foundations"),
    ("m2", "M2 · Enterprise↔Frontier"),
    ("m3", "M3 · Regulator Submission"),
    ("m4", "M4 · Kill-Switch & SARSP"),
    ("m5", "M5 · Treaty & Op-Model"),
    ("m6", "M6 · Pilot & Coalition"),
    ("m7", "M7 · Continuity & Constitution"),
    ("m8", "M8 · Ceremony & Codex"),
    ("m9", "M9 · Renewal Atlas & Adoption"),
    ("m10", "M10 · Attractor & Stewardship"),
    ("arch", "Architecture"),
    ("indices", "Indices"),
    ("cases", "Case Studies"),
    ("schemas", "Schemas"),
    ("code", "Code Examples"),
    ("api", "API"),
]
NAV = '<nav class="sn" aria-label="Sections"><ul>' + "".join(
    f'<li><a href="#{sid}">{esc(label)}</a></li>' for sid, label in nav_sections
) + '</ul></nav>'


# ──────────────────────────────────────────────────────────────────────────────
# SECTION: TOC + KPI STRIP + EXECUTIVE SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
toc_items = "".join(
    f'<a href="#{sid}"><span class="toc-num">{i:02d}</span>{esc(label)}</a>'
    for i, (sid, label) in enumerate(nav_sections, 1)
)

kpi_strip = f"""
<div class="kpi-grid">
  <div class="kpi"><div class="kv">10</div><div class="kl">Modules</div></div>
  <div class="kpi"><div class="kv">{len(DATA['indices'])}</div><div class="kl">Governance Indices</div></div>
  <div class="kpi"><div class="kv">{len(DATA['architecture']['planes'])}</div><div class="kl">Architecture Planes</div></div>
  <div class="kpi"><div class="kv">14</div><div class="kl">Core Principles</div></div>
  <div class="kpi"><div class="kv">L0-L4</div><div class="kl">Autonomy Levels</div></div>
  <div class="kpi"><div class="kv">≤60s</div><div class="kl">MTTK (Kill-Switch)</div></div>
  <div class="kpi"><div class="kv">10y</div><div class="kl">WORM Retention</div></div>
  <div class="kpi"><div class="kv">2050+</div><div class="kl">Terminal Horizon</div></div>
</div>
"""

exec_html = f"""
<section id="exec">
  <div class="toc">
    <div class="toc-title">📑 Table of Contents — {esc(doc_ref)} · v{esc(version)}</div>
    <div class="toc-list">{toc_items}</div>
  </div>
  <div class="sh">
    <h2>Executive Summary</h2><span class="sb">EXEC-SUM</span>
    <span class="badge bg-purple">Civilizational Horizon</span>
    <span class="badge bg-green">Regulator-Defensible</span>
    <span class="badge bg-cyan">Treaty-Aligned</span>
  </div>
  {kpi_strip}
  <div class="callout gold">
    <strong>Scope.</strong> A ten-module analytical framework synthesising enterprise AI governance (2026-2030), frontier AGI/ASI controls, regulator-defensible submission, systemic risk simulation, kill-switch validation, global interoperability &amp; treaty alignment, coalition activation, civilizational continuity &amp; constitution, covenant codex &amp; canon, ratification ceremony, renewal atlas, stewardship roadmap, and the <em>terminal governance attractor</em> aligning memory, meaning, action, and legitimacy under partial compliance.
  </div>
  <div class="section-inner">
    <p class="content" style="white-space:pre-wrap">{esc(DATA['executiveSummary'])}</p>
  </div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# SECTION RENDERER (generic per-section, handles all 10 modules)
# ──────────────────────────────────────────────────────────────────────────────
def render_section_body(sec):
    """Render a section's rich content based on known keys."""
    parts = []

    if sec.get("content"):
        parts.append(f"<p class='content'>{esc(sec['content'])}</p>")

    # M1 principles
    if "principles" in sec:
        cards = []
        for p in sec["principles"]:
            cites = ", ".join(p.get("citations", []))
            cards.append(f"""<div class="princ-card">
<div><span class="princ-num">{esc(p.get('id',''))}</span><span class="princ-name">{esc(p.get('name',''))}</span></div>
<div class="princ-stmt">{esc(p.get('statement',''))}</div>
<div class="princ-cite">🔗 {esc(cites)}</div>
</div>""")
        parts.append('<div class="g3">' + "".join(cards) + "</div>")

    # M2 architectural tiers
    if "tiers" in sec:
        parts.append(render_dict_list(sec["tiers"],
            [("tier", "Tier"), ("scope", "Scope"), ("autonomy", "Autonomy"),
             ("riskClass", "Risk Class"), ("governanceOverlay", "Governance Overlay")]))

    # M2 evaluations
    if "evaluations" in sec:
        parts.append(render_dict_list(sec["evaluations"],
            [("domain", "Domain"), ("evaluation", "Evaluation"), ("trigger", "Trigger"),
             ("passCriteria", "Pass Criteria")]))

    # M2 safety case structure
    if "structure" in sec and isinstance(sec["structure"], list):
        parts.append(render_dict_list(sec["structure"],
            [("step", "Step"), ("artefact", "Artefact"), ("evidence", "Evidence")]))

    # M2 closing charge template
    if "template" in sec:
        tpl = sec["template"]
        if isinstance(tpl, dict):
            parts.append(render_kv_table(tpl, ("Field", "Value")))
        else:
            parts.append(f"<pre class='code'>{esc(str(tpl))}</pre>")

    # M3 submission manifest / workflow / instruments
    for key, label in [("manifest", "Manifest"), ("steps", "Workflow Steps"),
                       ("instruments", "Compliance Instruments")]:
        if key in sec:
            items = sec[key]
            if isinstance(items, list) and items and isinstance(items[0], dict):
                # pick first few keys
                keys = list(items[0].keys())[:5]
                parts.append(render_dict_list(items, [(k, k.title()) for k in keys]))
            elif isinstance(items, list):
                parts.append(render_list(items))

    # M4 KSVP protocol / targets
    if "protocol" in sec:
        p = sec["protocol"]
        if isinstance(p, list) and p and isinstance(p[0], dict):
            keys = list(p[0].keys())[:5]
            parts.append(render_dict_list(p, [(k, k.title()) for k in keys]))
        elif isinstance(p, dict):
            parts.append(render_kv_table(p))
    if "targets" in sec:
        parts.append(render_kv_table(sec["targets"], ("Metric", "Target")))

    # M4 SARSP components / scenarios
    if "components" in sec and isinstance(sec["components"], list):
        if sec["components"] and isinstance(sec["components"][0], dict):
            keys = list(sec["components"][0].keys())[:4]
            parts.append(render_dict_list(sec["components"], [(k, k.title()) for k in keys]))
        else:
            parts.append(render_list(sec["components"]))
    if "scenarios" in sec:
        parts.append(render_dict_list(sec["scenarios"],
            [("id", "ID"), ("name", "Scenario"), ("trigger", "Trigger"),
             ("impact", "Impact"), ("response", "Response")]))

    # M4 mechanisms
    if "mechanisms" in sec and isinstance(sec["mechanisms"], list):
        if sec["mechanisms"] and isinstance(sec["mechanisms"][0], dict):
            keys = list(sec["mechanisms"][0].keys())[:5]
            parts.append(render_dict_list(sec["mechanisms"], [(k, k.title()) for k in keys]))
        else:
            parts.append(render_list(sec["mechanisms"]))

    # M5 interop layers / equivalence
    if "layers" in sec and isinstance(sec["layers"], list):
        if sec["layers"] and isinstance(sec["layers"][0], dict):
            keys = list(sec["layers"][0].keys())[:5]
            parts.append(render_dict_list(sec["layers"], [(k, k.title()) for k in keys]))
        else:
            parts.append(render_list(sec["layers"]))
    if "equivalenceCertificate" in sec:
        parts.append('<div class="callout green"><strong>Equivalence Certificate.</strong> '
                     + esc(json.dumps(sec["equivalenceCertificate"], ensure_ascii=False))[:420]
                     + "</div>")

    # M5 rings / signal flow
    if "rings" in sec:
        parts.append(render_dict_list(sec["rings"],
            [("ring", "Ring"), ("scope", "Scope"), ("composition", "Composition"),
             ("mandate", "Mandate")]))
    if "signalFlow" in sec:
        sf = sec["signalFlow"]
        if isinstance(sf, list):
            parts.append(render_list(sf))
        elif isinstance(sf, dict):
            parts.append(render_kv_table(sf))

    # M5 / M6 stages / phases / playbook
    for key, label in [("stages", "Stages"), ("phases", "Phases"),
                       ("playbook", "Playbook")]:
        if key in sec:
            items = sec[key]
            if isinstance(items, list) and items and isinstance(items[0], dict):
                keys = list(items[0].keys())[:5]
                parts.append(f"<h4 style='font-size:.82rem;margin:.6rem 0 .4rem;color:var(--t1);font-weight:700'>{label}</h4>")
                parts.append(render_dict_list(items, [(k, k.title()) for k in keys]))
            elif isinstance(items, list):
                parts.append(render_list(items))
            elif isinstance(items, dict):
                parts.append(render_kv_table(items))

    # M6 pilots
    if "pilots" in sec:
        parts.append(render_dict_list(sec["pilots"],
            [("id", "ID"), ("name", "Pilot"), ("region", "Region"),
             ("duration", "Duration"), ("outcomes", "Outcomes")]))
    if "preCommitments" in sec:
        parts.append("<h4 style='font-size:.82rem;margin:.6rem 0 .4rem;color:var(--t1);font-weight:700'>Pre-Commitments</h4>")
        parts.append(render_list(sec["preCommitments"]))

    # M7 continuity codex contents
    if "contents" in sec and isinstance(sec["contents"], list):
        if sec["contents"] and isinstance(sec["contents"][0], dict):
            keys = list(sec["contents"][0].keys())[:4]
            parts.append(render_dict_list(sec["contents"], [(k, k.title()) for k in keys]))
        else:
            parts.append(render_list(sec["contents"]))

    # M7 constitution articles
    if "articles" in sec:
        parts.append(render_dict_list(sec["articles"],
            [("article", "Art."), ("title", "Title"), ("essence", "Essence")]))
    if "amendment" in sec:
        parts.append('<div class="callout"><strong>Amendment Protocol.</strong> '
                     + esc(json.dumps(sec["amendment"], ensure_ascii=False))[:420] + "</div>")
    if "sunset" in sec:
        parts.append('<div class="callout red"><strong>Sunset Clause.</strong> '
                     + esc(json.dumps(sec["sunset"], ensure_ascii=False))[:320] + "</div>")

    # M8 ceremony / properties / canon layers / flow / kpis
    if "ceremony" in sec:
        parts.append('<div class="callout gold"><strong>Ceremony.</strong> '
                     + esc(json.dumps(sec["ceremony"], ensure_ascii=False))[:500] + "</div>")
    if "properties" in sec:
        parts.append(render_kv_table(sec["properties"]))
    # M9 layers already handled above

    if "flow" in sec and isinstance(sec["flow"], list):
        parts.append(render_list(sec["flow"]))

    if "performanceKpis" in sec:
        parts.append(render_kv_table(sec["performanceKpis"], ("KPI", "Target")))

    # M9 NFRs
    if "nfrs" in sec:
        parts.append(render_kv_table(sec["nfrs"], ("NFR", "Target")))

    # M10 attractor dimensions / deviation / steward / succession / protocol
    if "dimensions" in sec:
        if isinstance(sec["dimensions"], list) and sec["dimensions"] and isinstance(sec["dimensions"][0], dict):
            keys = list(sec["dimensions"][0].keys())[:4]
            parts.append(render_dict_list(sec["dimensions"], [(k, k.title()) for k in keys]))
        else:
            parts.append(render_list(sec["dimensions"]))
    if "attractorDeviation" in sec:
        parts.append('<div class="callout red"><strong>Attractor Deviation Detector.</strong> '
                     + esc(json.dumps(sec["attractorDeviation"], ensure_ascii=False))[:420] + "</div>")
    if "steward" in sec:
        s = sec["steward"]
        if isinstance(s, dict):
            parts.append(render_kv_table(s))
        else:
            parts.append(f"<p class='content'>{esc(s)}</p>")
    if "succession" in sec:
        s = sec["succession"]
        if isinstance(s, list):
            parts.append(render_list(s))
        elif isinstance(s, dict):
            parts.append(render_kv_table(s))

    return "\n".join(parts)


def render_module(mod_key, module_num, badge_cls="bg-purple"):
    """Render a whole module as a <section>."""
    mod = DATA[mod_key]
    anchor = f"m{module_num}"
    parts = [f"""<section id="{anchor}">
  <div class="sh">
    <h2>M{module_num} · {esc(mod['title'])}</h2>
    <span class="sb">{esc(mod['id'])}</span>
    <span class="badge {badge_cls}">Module {module_num}</span>
  </div>
  <p class="sd">{esc(mod.get('summary',''))}</p>"""]

    for sec in mod.get("sections", []):
        body = render_section_body(sec)
        parts.append(f"""<div class="section-inner">
<h3><span class="sid">{esc(sec.get('id',''))}</span>{esc(sec.get('title',''))}</h3>
{body}
</div>""")
    parts.append("</section>")
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────────
# ARCHITECTURE
# ──────────────────────────────────────────────────────────────────────────────
arch = DATA["architecture"]
plane_cards = []
for i, p in enumerate(arch["planes"], 1):
    comp = render_list(p.get("components", []))
    plane_cards.append(f"""<div class="plane-card">
<h3><span class="plane-num">{i}</span>{esc(p['plane'])}</h3>
<p style="font-size:.78rem;color:var(--t2);margin-bottom:.5rem">{esc(p.get('purpose',''))}</p>
{comp}
</div>""")

arch_html = f"""
<section id="arch">
  <div class="sh">
    <h2>Civilizational Architecture — 5 Planes</h2>
    <span class="sb">ARCH</span>
    <span class="badge bg-indigo">Institutional</span>
    <span class="badge bg-purple">Regulator-Defensible</span>
  </div>
  <p class="sd">{esc(arch.get('description',''))}</p>
  <div class="g3">{"".join(plane_cards)}</div>
  <div class="callout" style="margin-top:1rem"><strong>Relationship.</strong> {esc(arch.get('relationship',''))}</div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# INDICES
# ──────────────────────────────────────────────────────────────────────────────
idx_cards = []
for idx in DATA["indices"]:
    inputs = render_list(idx.get("inputs", []))
    idx_cards.append(f"""<div class="card">
<span class="code">{esc(idx['id'])}</span>
<h3>{esc(idx['name'])}</h3>
<p>{esc(idx.get('description',''))}</p>
<p><strong style="color:var(--cyan);font-size:.72rem">Inputs:</strong></p>
{inputs}
<p><strong style="color:var(--amber);font-size:.72rem">Range:</strong> <span class="mn" style="color:var(--t1)">{esc(idx.get('range',''))}</span></p>
<p><strong style="color:var(--red);font-size:.72rem">Trigger:</strong> <span class="mn" style="color:var(--t1)">{esc(idx.get('trigger',''))}</span></p>
</div>""")

indices_html = f"""
<section id="indices">
  <div class="sh">
    <h2>Governance Indices — CAI-RB & Related</h2>
    <span class="sb">INDICES</span>
    <span class="badge bg-cyan">Treaty-Published</span>
  </div>
  <p class="sd">Composite indices operationalise systemic risk monitoring, attractor alignment, coalition trigger thresholds, and cross-jurisdictional signal fusion. Published monthly by the treaty body.</p>
  <div class="g3">{"".join(idx_cards)}</div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# CASE STUDIES
# ──────────────────────────────────────────────────────────────────────────────
cs_cards = []
for cs in DATA["caseStudies"]:
    outcomes = cs.get("outcomes", {})
    if isinstance(outcomes, dict):
        out_rows = "".join(f"<tr><td class='mn'>{esc(k)}</td><td>{esc(v)}</td></tr>"
                           for k, v in outcomes.items())
        outcomes_html = f"<div class='tc'><table><tbody>{out_rows}</tbody></table></div>"
    else:
        outcomes_html = f"<p style='font-size:.75rem;color:var(--t2)'>{esc(outcomes)}</p>"

    cs_cards.append(f"""<div class="card">
<span class="code">{esc(cs['id'])}</span>
<h3>{esc(cs['name'])}</h3>
<p><strong style="color:var(--cyan)">Participants:</strong> {esc(cs.get('participants',''))}</p>
<p><strong style="color:var(--amber)">Scope:</strong> {esc(cs.get('scope',''))}</p>
<p><strong style="color:var(--green)">Outcomes:</strong></p>
{outcomes_html}
<div class="callout green" style="margin-top:.5rem"><strong>Lesson.</strong> {esc(cs.get('lesson',''))}</div>
</div>""")

cases_html = f"""
<section id="cases">
  <div class="sh">
    <h2>Reference Case Studies</h2>
    <span class="sb">CASE-STUDIES</span>
    <span class="badge bg-green">Pilot Outcomes</span>
  </div>
  <p class="sd">Illustrative 2027-2030 coalition pilots and institutional deployments demonstrating operational feasibility of the civilizational stack.</p>
  <div class="g2">{"".join(cs_cards)}</div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# SCHEMAS
# ──────────────────────────────────────────────────────────────────────────────
schema_cards = []
for name, schema in DATA["schemas"].items():
    pretty = json.dumps(schema, indent=2, ensure_ascii=False)
    if len(pretty) > 2200:
        pretty = pretty[:2200] + "\n... [truncated for display; full via /api/civ-ai-gov/schemas/" + name + "]"
    schema_cards.append(f"""<div class="card">
<span class="code">{esc(name)}</span>
<h3>{esc(schema.get('$id','').split('/')[-1] or name)}</h3>
<p>JSON Schema — {esc(schema.get('$schema','draft'))}</p>
<pre class="code">{esc(pretty)}</pre>
</div>""")

schemas_html = f"""
<section id="schemas">
  <div class="sh">
    <h2>JSON Schemas</h2>
    <span class="sb">SCHEMAS</span>
    <span class="badge bg-blue">Wire-Level</span>
  </div>
  <p class="sd">Authoritative JSON Schemas for core civilizational artefacts: Constitution Articles, Closing Charges, Covenant Codex Entries.</p>
  <div class="g2">{"".join(schema_cards)}</div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# CODE EXAMPLES
# ──────────────────────────────────────────────────────────────────────────────
code_cards = []
_lang_map = {
    "killSwitchRegistry": ("Python", "Kill-Switch Registry (KSR) — reference implementation"),
    "attractorDeviation": ("Python", "Attractor Deviation — composite distance from terminal attractor"),
    "equivalenceCertificate": ("JSON Schema", "Equivalence Certificate — cross-jurisdictional recognition"),
    "regoCivCore": ("Rego / OPA", "Civilizational Core Policy — universal minimum obligations"),
    "sarspYaml": ("YAML", "SARSP Scenario Definition — Systemic AI Risk Simulation Playbook"),
}
for name, ex in DATA["codeExamples"].items():
    if isinstance(ex, dict):
        lang = ex.get("language", "text")
        code = ex.get("code", "")
        desc = ex.get("description", "")
        title = ex.get("title", name)
    else:
        lang, desc = _lang_map.get(name, ("text", ""))
        code = ex
        title = name
    if len(code) > 2800:
        code = code[:2800] + "\n# ... [truncated; full via /api/civ-ai-gov/code-examples/" + name + "]"
    code_cards.append(f"""<div class="card">
<span class="code">{esc(name)}</span>
<h3>{esc(title)}</h3>
<p>{esc(desc)}</p>
<div class="badge bg-cyan">{esc(lang)}</div>
<pre class="code">{esc(code)}</pre>
</div>""")

code_html = f"""
<section id="code">
  <div class="sh">
    <h2>Reference Code Examples</h2>
    <span class="sb">CODE</span>
    <span class="badge bg-indigo">Reference Implementation</span>
  </div>
  <p class="sd">Production-oriented reference implementations: kill-switch registry, attractor deviation detector, equivalence certificate, Rego civ-core policy, SARSP YAML.</p>
  <div class="g2">{"".join(code_cards)}</div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# API SECTION
# ──────────────────────────────────────────────────────────────────────────────
api_rows = [
    ("GET", "/api/civ-ai-gov", "Full blueprint payload"),
    ("GET", "/api/civ-ai-gov/meta", "Metadata"),
    ("GET", "/api/civ-ai-gov/summary", "Aggregate counts and KPIs"),
    ("GET", "/api/civ-ai-gov/executive-summary", "Executive summary (text/plain)"),
    ("GET", "/api/civ-ai-gov/architecture", "Five-plane architecture"),
    ("GET", "/api/civ-ai-gov/principles", "14 first principles"),
    ("GET", "/api/civ-ai-gov/m1..m10", "Module root (with sections & summary)"),
    ("GET", "/api/civ-ai-gov/m{n}/sections", "Module sections list"),
    ("GET", "/api/civ-ai-gov/m{n}/sections/:id", "Specific section by ID (e.g. M4-S1)"),
    ("GET", "/api/civ-ai-gov/regulator-pack", "Regulator submission pack"),
    ("GET", "/api/civ-ai-gov/closing-charge", "Closing charge"),
    ("GET", "/api/civ-ai-gov/kill-switch", "Kill-Switch Validation Protocol (KSVP)"),
    ("GET", "/api/civ-ai-gov/sarsp", "Systemic AI Risk Simulation Playbook"),
    ("GET", "/api/civ-ai-gov/treaty", "Global treaty & interop"),
    ("GET", "/api/civ-ai-gov/operating-model", "Global AI governance operating model"),
    ("GET", "/api/civ-ai-gov/pilot-roadmap", "Pilot deployment roadmap"),
    ("GET", "/api/civ-ai-gov/coalition", "Coalition activation playbook"),
    ("GET", "/api/civ-ai-gov/continuity-codex", "Global Governance Continuity Codex"),
    ("GET", "/api/civ-ai-gov/constitution", "Civilizational AI Governance Constitution"),
    ("GET", "/api/civ-ai-gov/ceremony", "Ratification ceremony playbook"),
    ("GET", "/api/civ-ai-gov/codex-canon", "Codex Canon"),
    ("GET", "/api/civ-ai-gov/covenant", "Civilizational Covenant Codex"),
    ("GET", "/api/civ-ai-gov/renewal-atlas", "Renewal Atlas (technical architecture)"),
    ("GET", "/api/civ-ai-gov/adoption", "Institutional Adoption Playbook"),
    ("GET", "/api/civ-ai-gov/attractor", "Terminal Governance Attractor"),
    ("GET", "/api/civ-ai-gov/stewardship", "Stewardship roadmap"),
    ("GET", "/api/civ-ai-gov/terminal-closure", "Terminal closure & dissolution protocol"),
    ("GET", "/api/civ-ai-gov/indices", "Governance indices (CAI-RB etc.)"),
    ("GET", "/api/civ-ai-gov/indices/:id", "Specific index (IDX-1..IDX-8)"),
    ("GET", "/api/civ-ai-gov/case-studies", "Reference case studies"),
    ("GET", "/api/civ-ai-gov/case-studies/:id", "Specific case (CS-C1..CS-C5)"),
    ("GET", "/api/civ-ai-gov/schemas", "JSON schemas"),
    ("GET", "/api/civ-ai-gov/schemas/:name", "Specific schema by name"),
    ("GET", "/api/civ-ai-gov/code-examples", "Reference code examples"),
    ("GET", "/api/civ-ai-gov/code-examples/:name", "Specific code example by name"),
]
api_rows_html = "".join(
    f"<tr><td><span class='badge bg-green'>{esc(m)}</span></td>"
    f"<td><code class='mn' style='color:var(--cyan)'>{esc(path)}</code></td>"
    f"<td>{esc(desc)}</td></tr>" for m, path, desc in api_rows
)

api_html = f"""
<section id="api">
  <div class="sh">
    <h2>API Endpoints (72+)</h2>
    <span class="sb">API</span>
    <span class="badge bg-green">Live</span>
    <span class="badge bg-purple">JSON</span>
  </div>
  <p class="sd">All endpoints return JSON (except <code class='mn'>/executive-summary</code> which is text/plain). All module sections are addressable via <code class='mn'>/api/civ-ai-gov/m{{n}}/sections/:id</code> where <code class='mn'>:id</code> follows the <code class='mn'>M{{n}}-S{{k}}</code> pattern.</p>
  <div class="tc"><table id="api-list">
    <thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead>
    <tbody>{api_rows_html}</tbody>
  </table></div>
</section>
"""


# ──────────────────────────────────────────────────────────────────────────────
# ASSEMBLE
# ──────────────────────────────────────────────────────────────────────────────
MAIN_OPEN = '<main id="main">'
MAIN_CLOSE = '</main>'

module_badges = ["bg-cyan", "bg-indigo", "bg-red", "bg-amber", "bg-blue",
                 "bg-green", "bg-purple", "bg-pink", "bg-gold", "bg-red"]
modules_html = "\n".join(
    render_module(k, i, module_badges[i - 1])
    for i, k in enumerate([
        "m1_foundations", "m2_enterpriseFrontier", "m3_regulatorSubmission",
        "m4_killSwitchSimulation", "m5_interopTreatyOpModel",
        "m6_pilotRoadmapCoalition", "m7_continuityConstitution",
        "m8_ceremonyCodexCanon", "m9_renewalAtlasAdoption",
        "m10_attractorStewardship",
    ], 1)
)

FOOTER = f"""
<div class="footer">
  <p>{esc(doc_ref)} · v{esc(version)} · {esc(meta.get('date',''))} · Classification: {esc(classification)}</p>
  <p>Civilizational AI Governance Stack 2026-2050+ · RAG Agentic AI Governance Dashboard · <a href="/governance-hub.html">Governance Hub</a> · <a href="/ent-ai-gov-blueprint.html">Enterprise Blueprint (WP-030)</a></p>
  <p style="margin-top:.3rem">Aligned with NIST AI RMF 1.0 · ISO/IEC 42001:2023 · EU AI Act · GDPR · SR 11-7 · Sector model-risk standards</p>
</div>
"""

HTML = (HEAD + HERO + NAV + MAIN_OPEN + exec_html + modules_html
        + arch_html + indices_html + cases_html + schemas_html + code_html
        + api_html + MAIN_CLOSE + FOOTER + """
<script>
// nav highlight on scroll
const sections=document.querySelectorAll('main section[id]');
const navLinks=document.querySelectorAll('nav.sn a[href^="#"]');
const io=new IntersectionObserver((entries)=>{entries.forEach(e=>{if(e.isIntersecting){const id=e.target.id;navLinks.forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+id))}})},{rootMargin:'-40% 0px -55% 0px'});
sections.forEach(s=>io.observe(s));
</script>
</body></html>""")

OUT.write_text(HTML, encoding="utf-8")
print(f"Wrote {OUT} ({OUT.stat().st_size // 1024} KB, {HTML.count(chr(10))+1} lines)")
print(f"Modules rendered: 10 | Sections: {sum(len(DATA[k]['sections']) for k in DATA if k.startswith('m') and '_' in k)}")
print(f"Indices: {len(DATA['indices'])} | Planes: {len(DATA['architecture']['planes'])}")
print(f"Case studies: {len(DATA['caseStudies'])} | Schemas: {len(DATA['schemas'])} | Code examples: {len(DATA['codeExamples'])}")
