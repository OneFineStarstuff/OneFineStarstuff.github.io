#!/usr/bin/env python3
"""Render WP-032 Six-Layer Civilizational AI Governance Blueprint (CRS-UUID-001)
as a regulator-ready HTML dashboard."""

import json
import html
from pathlib import Path

HERE = Path(__file__).parent
DATA = json.load(open(HERE / "data" / "civ-ai-gov-6l-crs.json"))
OUT  = HERE / "public" / "civ-ai-gov-6l-crs.html"


def esc(s):
    if s is None:
        return ""
    return html.escape(str(s))


def render_list(items):
    if not items:
        return ""
    return '<ul class="ul-tight">' + "".join(
        f"<li>{esc(x)}</li>" if isinstance(x, str) else
        f"<li>{esc(json.dumps(x, ensure_ascii=False))}</li>"
        for x in items
    ) + "</ul>"


def render_dict_list(items, fields):
    """fields: list of (key, label)"""
    if not items or not all(isinstance(x, dict) for x in items):
        return render_list([str(x) for x in items] if items else [])
    thead = "".join(f"<th>{esc(label)}</th>" for _, label in fields)
    rows = []
    for it in items:
        tds = []
        for k, _ in fields:
            v = it.get(k, "")
            if isinstance(v, list):
                v = "<br>".join(f"• {esc(x)}" if isinstance(x, str)
                                else f"• {esc(json.dumps(x, ensure_ascii=False))[:120]}"
                                for x in v)
                tds.append(f"<td>{v}</td>")
            elif isinstance(v, dict):
                tds.append(f"<td><code class='mn'>{esc(json.dumps(v, ensure_ascii=False))[:200]}</code></td>")
            else:
                tds.append(f"<td>{esc(v)}</td>")
        rows.append("<tr>" + "".join(tds) + "</tr>")
    return f"<div class='tc'><table><thead><tr>{thead}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"


def render_kv(obj, headers=("Key", "Value")):
    if obj is None:
        return ""
    if isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            keys = list(obj[0].keys())[:6]
            return render_dict_list(obj, [(k, k.replace('_', ' ').title()) for k in keys])
        return render_list([str(x) for x in obj])
    if not isinstance(obj, dict):
        return f"<p class='content'>{esc(str(obj))}</p>"
    rows = []
    for k, v in obj.items():
        if isinstance(v, (list, dict)):
            v_display = json.dumps(v, ensure_ascii=False)
            if len(v_display) > 200:
                v_display = v_display[:200] + "…"
            rows.append(f"<tr><td class='mn'>{esc(k)}</td><td><code class='mn'>{esc(v_display)}</code></td></tr>")
        else:
            rows.append(f"<tr><td class='mn'>{esc(k)}</td><td>{esc(v)}</td></tr>")
    return f"<div class='tc'><table><thead><tr><th>{esc(headers[0])}</th><th>{esc(headers[1])}</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>"


meta = DATA["meta"]
subj = meta["subjectSystem"]

# ─────────────────────────────────────────────────────────────────────────────
# HEAD
# ─────────────────────────────────────────────────────────────────────────────
HEAD = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(meta['docRef'])} — Six-Layer Civilizational AI Governance Blueprint · CRS-UUID-001</title>
<meta name="description" content="Regulator-ready six-layer civilizational AI governance blueprint centered on CRS-UUID-001 (Credit Risk Scoring AI at Global Bank plc). EU AI Act Annex IV · SR 11-7 · Basel III/ICAAP · ISO/IEC 42001 · GDPR · FCRA/ECOA · GAGCOT GC1-GC7. Evidence bundles, OPA/Rego policies, CI/CD gates, supervisory replay, treaty charter.">
<meta name="doc-ref" content="{esc(meta['docRef'])}">
<meta name="doc-version" content="{esc(meta['version'])}">
<meta name="classification" content="{esc(meta['classification'])}">
<style>
:root{{--bg:#07090f;--bg2:#0d1220;--card:#141b2e;--card-h:#1a2342;--t1:#e5e9f0;--t2:#94a3b8;--t3:#64748b;--blue:#3b82f6;--cyan:#06b6d4;--green:#10b981;--amber:#f59e0b;--red:#ef4444;--purple:#8b5cf6;--pink:#ec4899;--indigo:#6366f1;--gold:#eab308;--emerald:#059669;--b1:#1e293b;--b2:#334155;--mono:'Cascadia Code','Fira Code',monospace;--sans:'Inter',-apple-system,sans-serif;--r:12px;--rs:8px;--tr:all .3s cubic-bezier(.4,0,.2,1)}}
*,*::before,*::after{{margin:0;padding:0;box-sizing:border-box}}
html{{scroll-behavior:smooth;font-size:15px}}
body{{font-family:var(--sans);background:var(--bg);color:var(--t1);line-height:1.6;overflow-x:hidden}}
a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}
.skip{{position:absolute;top:-100px;left:8px;background:var(--blue);color:#fff;padding:8px 16px;border-radius:6px;z-index:9999;font-size:.85rem}}.skip:focus{{top:8px}}
.hero{{background:linear-gradient(135deg,#0b0f24,#1b1240 45%,#0c1a22);padding:2rem 1.5rem 1.5rem;border-bottom:1px solid var(--b1);position:relative;overflow:hidden}}
.hero::before{{content:'';position:absolute;top:-50%;right:-20%;width:70%;height:200%;background:radial-gradient(ellipse,rgba(16,185,129,.06),transparent 70%);pointer-events:none}}
.hero-inner{{max-width:1600px;margin:0 auto;position:relative}}
.badge-doc{{display:inline-flex;align-items:center;gap:6px;background:rgba(16,185,129,.14);color:var(--green);padding:4px 12px;border-radius:20px;font-size:.72rem;font-weight:700;letter-spacing:.5px;text-transform:uppercase;margin-bottom:.75rem;border:1px solid rgba(16,185,129,.25)}}
.hero h1{{font-size:1.75rem;font-weight:800;letter-spacing:-.02em;margin-bottom:.35rem;background:linear-gradient(135deg,#e2e8f0,#94a3b8 60%,#6ee7b7);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.hero-sub{{color:var(--t2);font-size:.85rem;max-width:1200px}}
.hero-meta{{display:flex;flex-wrap:wrap;gap:1.25rem;margin-top:1rem}}
.hero-meta-item{{display:flex;align-items:center;gap:6px;font-size:.72rem;color:var(--t3)}}.hero-meta-item strong{{color:var(--t2)}}
.live-badge{{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.5px;background:rgba(16,185,129,.14);color:var(--green);border:1px solid rgba(16,185,129,.25)}}
.live-dot{{width:6px;height:6px;border-radius:50%;background:currentColor;animation:pd 2s infinite}}@keyframes pd{{0%,100%{{opacity:1}}50%{{opacity:.35}}}}
.status-bar{{background:var(--bg2);border-bottom:1px solid var(--b1);padding:.5rem 1.5rem;display:flex;gap:1.5rem;flex-wrap:wrap;font-size:.7rem}}
.si{{display:flex;align-items:center;gap:5px;color:var(--t3)}}.si .v{{color:var(--cyan);font-weight:600;font-family:var(--mono)}}
nav.sn{{background:var(--bg2);border-bottom:1px solid var(--b1);padding:0 1.5rem;position:sticky;top:0;z-index:100;overflow-x:auto}}
nav.sn ul{{list-style:none;display:flex;max-width:1600px;margin:0 auto}}
nav.sn li a{{display:block;padding:.7rem .85rem;font-size:.7rem;font-weight:500;color:var(--t3);white-space:nowrap;border-bottom:2px solid transparent;transition:var(--tr)}}
nav.sn li a:hover{{color:var(--t1);background:rgba(16,185,129,.06);text-decoration:none}}
nav.sn li a.active{{color:var(--green);border-bottom-color:var(--green)}}
main{{max-width:1600px;margin:0 auto;padding:1.5rem}}
section{{margin-bottom:2.5rem;scroll-margin-top:60px}}
.sh{{display:flex;align-items:center;gap:10px;margin-bottom:1.1rem;padding-bottom:.75rem;border-bottom:1px solid var(--b1);flex-wrap:wrap}}
.sh h2{{font-size:1.2rem;font-weight:700}}
.sb{{display:inline-block;background:rgba(16,185,129,.1);color:var(--green);padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;font-family:var(--mono)}}
.sd{{color:var(--t2);font-size:.83rem;margin-bottom:1rem;max-width:1200px;line-height:1.7}}
.g2{{display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:1rem}}
.g3{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:1rem}}
.g4{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.85rem}}
.card{{background:linear-gradient(145deg,rgba(30,41,59,.55),rgba(15,23,42,.8));border:1px solid var(--b1);border-radius:var(--r);padding:1.1rem;transition:var(--tr);box-shadow:0 4px 24px rgba(0,0,0,.3)}}
.card:hover{{border-color:var(--b2);box-shadow:0 0 22px rgba(16,185,129,.15);transform:translateY(-1px)}}
.card h3{{font-size:.9rem;font-weight:700;margin-bottom:.4rem;color:var(--t1)}}
.card .code{{display:inline-block;font-family:var(--mono);font-size:.65rem;color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 6px;border-radius:3px;margin-bottom:.4rem}}
.card p{{font-size:.78rem;color:var(--t2);line-height:1.65;margin-bottom:.5rem}}
.kpi-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(165px,1fr));gap:.75rem;margin-bottom:1.25rem}}
.kpi{{background:linear-gradient(145deg,rgba(30,41,59,.6),rgba(15,23,42,.85));border:1px solid var(--b1);border-radius:var(--rs);padding:.9rem;text-align:center;transition:var(--tr)}}
.kpi:hover{{border-color:var(--green);box-shadow:0 0 20px rgba(16,185,129,.2)}}
.kv{{font-size:1.5rem;font-weight:800;font-family:var(--mono);background:linear-gradient(135deg,var(--cyan),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.kl{{font-size:.68rem;color:var(--t3);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
.badge{{display:inline-flex;align-items:center;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;text-transform:uppercase;letter-spacing:.3px;font-family:var(--mono);margin:1px}}
.bg-blue{{background:rgba(59,130,246,.12);color:var(--blue)}}.bg-green{{background:rgba(16,185,129,.12);color:var(--green)}}
.bg-amber{{background:rgba(245,158,11,.12);color:var(--amber)}}.bg-red{{background:rgba(220,38,38,.12);color:var(--red)}}
.bg-purple{{background:rgba(139,92,246,.12);color:var(--purple)}}.bg-pink{{background:rgba(236,72,153,.12);color:var(--pink)}}
.bg-cyan{{background:rgba(6,182,212,.12);color:var(--cyan)}}.bg-indigo{{background:rgba(99,102,241,.12);color:var(--indigo)}}
.bg-gold{{background:rgba(234,179,8,.15);color:var(--gold)}}.bg-emerald{{background:rgba(5,150,105,.15);color:var(--emerald)}}
.tc{{overflow-x:auto;border-radius:var(--rs);border:1px solid var(--b1);margin:.5rem 0}}
table{{width:100%;border-collapse:collapse;font-size:.77rem}}
thead{{background:rgba(15,23,42,.6)}}
th{{padding:.5rem .75rem;text-align:left;font-weight:600;color:var(--t2);font-size:.68rem;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--b1)}}
td{{padding:.5rem .75rem;border-bottom:1px solid var(--b1);color:var(--t1);vertical-align:top}}
tr:hover td{{background:rgba(16,185,129,.04)}}
.mn{{font-family:var(--mono);font-size:.72rem}}
.toc{{background:var(--card);border:1px solid var(--b1);border-radius:var(--r);padding:1.1rem;margin-bottom:1.5rem}}
.toc-title{{font-size:.85rem;font-weight:700;margin-bottom:.75rem;color:var(--t1)}}
.toc-list{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.25rem}}
.toc-list a{{display:flex;align-items:center;gap:6px;padding:4px 8px;font-size:.72rem;color:var(--t2);border-radius:4px;transition:var(--tr)}}
.toc-list a:hover{{background:rgba(16,185,129,.06);color:var(--green);text-decoration:none}}
.toc-list .toc-num{{color:var(--cyan);font-family:var(--mono);font-weight:600;min-width:28px}}
.layer-card{{background:linear-gradient(145deg,rgba(16,185,129,.07),rgba(30,41,59,.6));border:1px solid rgba(16,185,129,.22);border-radius:var(--r);padding:1.2rem;transition:var(--tr)}}
.layer-card:hover{{border-color:var(--green);box-shadow:0 0 25px rgba(16,185,129,.18)}}
.layer-head{{display:flex;align-items:center;gap:10px;margin-bottom:.5rem}}
.layer-num{{background:linear-gradient(135deg,var(--green),var(--cyan));color:#fff;width:38px;height:38px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.95rem;font-family:var(--mono)}}
.layer-title{{font-size:1rem;font-weight:700;color:var(--t1)}}
.layer-id{{font-size:.65rem;color:var(--green);font-family:var(--mono);text-transform:uppercase;letter-spacing:.5px}}
.ul-tight{{list-style:none;padding-left:0;font-size:.75rem;color:var(--t2);line-height:1.7}}
.ul-tight li{{padding:3px 0;padding-left:14px;position:relative}}
.ul-tight li::before{{content:'▸';position:absolute;left:0;color:var(--cyan)}}
pre.code{{background:#05070c;border:1px solid var(--b1);border-radius:var(--rs);padding:.9rem;overflow-x:auto;font-family:var(--mono);font-size:.72rem;color:#cbd5e1;line-height:1.55;margin:.5rem 0}}
.callout{{border-left:3px solid var(--green);background:rgba(16,185,129,.05);padding:.8rem 1rem;border-radius:0 var(--rs) var(--rs) 0;margin:.5rem 0;font-size:.78rem;color:var(--t2);line-height:1.7}}
.callout.gold{{border-left-color:var(--gold);background:rgba(234,179,8,.05)}}
.callout.red{{border-left-color:var(--red);background:rgba(239,68,68,.05)}}
.callout.blue{{border-left-color:var(--blue);background:rgba(59,130,246,.05)}}
.callout.purple{{border-left-color:var(--purple);background:rgba(139,92,246,.05)}}
.callout strong{{color:var(--t1)}}
.subsec{{background:linear-gradient(145deg,rgba(30,41,59,.4),rgba(15,23,42,.65));border:1px solid var(--b1);border-radius:var(--r);padding:1rem;margin-bottom:1rem}}
.subsec h4{{font-size:.88rem;font-weight:700;color:var(--t1);margin-bottom:.5rem;display:flex;align-items:center;gap:8px}}
.subsec .sid{{font-family:var(--mono);font-size:.65rem;color:var(--cyan);background:rgba(6,182,212,.1);padding:1px 7px;border-radius:4px}}
.subject-card{{background:linear-gradient(145deg,rgba(6,182,212,.08),rgba(30,41,59,.65));border:1px solid rgba(6,182,212,.28);border-radius:var(--r);padding:1.2rem;margin-bottom:1.25rem}}
.subject-card h3{{color:var(--cyan);font-size:1rem;font-weight:700;margin-bottom:.5rem}}
.subject-kv{{display:grid;grid-template-columns:200px 1fr;gap:.3rem .75rem;font-size:.78rem}}
.subject-kv dt{{color:var(--t3);font-family:var(--mono);font-size:.7rem}}.subject-kv dd{{color:var(--t1)}}
.gc-card{{background:linear-gradient(145deg,rgba(239,68,68,.05),rgba(30,41,59,.6));border:1px solid rgba(239,68,68,.18);border-radius:var(--r);padding:1rem;transition:var(--tr)}}
.gc-card:hover{{border-color:var(--red);box-shadow:0 0 18px rgba(239,68,68,.12)}}
.gc-id{{display:inline-block;background:rgba(239,68,68,.15);color:var(--red);padding:1px 8px;border-radius:4px;font-family:var(--mono);font-weight:700;font-size:.7rem;margin-bottom:.4rem}}
.footer{{border-top:1px solid var(--b1);padding:2rem 1.5rem;text-align:center;color:var(--t3);font-size:.72rem;margin-top:3rem;background:var(--bg2)}}
.footer a{{color:var(--green)}}
@media(max-width:768px){{.hero h1{{font-size:1.35rem}}.g2,.g3{{grid-template-columns:1fr}}.subject-kv{{grid-template-columns:1fr}}}}
</style>
</head>
<body>
<a href="#main" class="skip">Skip to content</a>
"""

# ─────────────────────────────────────────────────────────────────────────────
# HERO + STATUS
# ─────────────────────────────────────────────────────────────────────────────
hero_meta_items = "".join(f"<span class='hero-meta-item'>🔖 <strong>{esc(k)}:</strong> {esc(v)}</span>"
                          for k, v in [
                              ("Doc-Ref",     meta['docRef']),
                              ("Version",     meta['version']),
                              ("Date",        meta['date']),
                              ("Subject",     subj['modelId']),
                              ("Risk-Tier",   "EU AI Act High-Risk · SR 11-7 Tier-1"),
                              ("Classification", meta['classification']),
                          ])

HERO = f"""
<div class="hero">
  <div class="hero-inner">
    <span class="badge-doc">◆ Regulator-Ready · Board-Defensible · Treaty-Aligned</span>
    <h1>Six-Layer Civilizational AI Governance Blueprint — CRS-UUID-001</h1>
    <p class="hero-sub">End-to-end governance reference implementation for <strong>{esc(subj['modelName'])}</strong>, a Tier-1 EU AI Act high-risk credit-risk scoring AI at Global Bank plc. Spans six layers: <strong>Institutional (SR 11-7 / ISO 42001 / Annex IV)</strong> → <strong>Systemic (PRA / FCA / OCC / ICAAP)</strong> → <strong>Frontier Compute (custody, kill-switch)</strong> → <strong>Geopolitical Treaty (GAGCOT · GC1-GC7)</strong> → <strong>Autonomous Mesh (OPA/Rego · CI/CD · cryptographic evidence)</strong> → <strong>Adversarial Co-Evolution (red-team · threat intel · kill-chain)</strong>.</p>
    <div class="hero-meta">{hero_meta_items}<span class="live-badge"><span class="live-dot"></span> Live API</span></div>
  </div>
</div>
<div class="status-bar">
  <span class="si">Layers: <span class="v">6</span></span>
  <span class="si">Simulations: <span class="v">13</span></span>
  <span class="si">GC Scenarios: <span class="v">7</span></span>
  <span class="si">OPA Policies: <span class="v">12</span></span>
  <span class="si">CI/CD Gates: <span class="v">14</span></span>
  <span class="si">Evidence Bundles: <span class="v">9</span></span>
  <span class="si">HSRs: <span class="v">8</span></span>
  <span class="si">Treaty Articles: <span class="v">12</span></span>
  <span class="si">Regulators: <span class="v">PRA·FCA·OCC·Fed·ECB·CFPB·ICO</span></span>
</div>
"""

# ─────────────────────────────────────────────────────────────────────────────
# NAV
# ─────────────────────────────────────────────────────────────────────────────
nav_sections = [
    ("exec",     "Executive Summary"),
    ("subject",  "Subject System"),
    ("L1",       "L1 · Institutional"),
    ("L2",       "L2 · Systemic"),
    ("L3",       "L3 · Frontier Compute"),
    ("L4",       "L4 · Treaty & GC1-GC7"),
    ("L5",       "L5 · Autonomous Mesh"),
    ("L6",       "L6 · Adversarial Co-Evo"),
    ("annexiv",  "Annex IV Dossier"),
    ("capital",  "Capital Impact"),
    ("validation","IMV Report"),
    ("simulations","Simulations"),
    ("schemas",  "Schemas"),
    ("code",     "Code Examples"),
    ("api",      "API"),
]
NAV = '<nav class="sn" aria-label="Sections"><ul>' + "".join(
    f'<li><a href="#{sid}">{esc(label)}</a></li>' for sid, label in nav_sections
) + '</ul></nav>'

# ─────────────────────────────────────────────────────────────────────────────
# EXEC SUMMARY + TOC
# ─────────────────────────────────────────────────────────────────────────────
toc_items = "".join(
    f'<a href="#{sid}"><span class="toc-num">{i:02d}</span>{esc(label)}</a>'
    for i, (sid, label) in enumerate(nav_sections, 1)
)

kpi_strip = """
<div class="kpi-grid">
  <div class="kpi"><div class="kv">6</div><div class="kl">Governance Layers</div></div>
  <div class="kpi"><div class="kv">13</div><div class="kl">Multi-Layer Simulations</div></div>
  <div class="kpi"><div class="kv">GC1-GC7</div><div class="kl">Treaty Crisis Scenarios</div></div>
  <div class="kpi"><div class="kv">12</div><div class="kl">OPA/Rego Policies</div></div>
  <div class="kpi"><div class="kv">14</div><div class="kl">CI/CD Gates</div></div>
  <div class="kpi"><div class="kv">9</div><div class="kl">Evidence Bundles</div></div>
  <div class="kpi"><div class="kv">≤60s</div><div class="kl">Kill-Switch MTTR</div></div>
  <div class="kpi"><div class="kv">≤72h</div><div class="kl">Replay SLA</div></div>
</div>
"""

exec_html = f"""
<section id="exec">
  <div class="toc">
    <div class="toc-title">📑 Table of Contents — {esc(meta['docRef'])} · v{esc(meta['version'])}</div>
    <div class="toc-list">{toc_items}</div>
  </div>
  <div class="sh">
    <h2>Executive Summary</h2><span class="sb">EXEC-SUM</span>
    <span class="badge bg-green">Regulator-Ready</span>
    <span class="badge bg-purple">Treaty-Aligned</span>
    <span class="badge bg-cyan">Board-Defensible</span>
  </div>
  {kpi_strip}
  <div class="callout gold">
    <strong>Purpose.</strong> Operationalise civilizational AI governance around a single concrete system
    (CRS-UUID-001), producing board, supervisor, auditor, and treaty-ready dossiers, audit packs, evidence
    bundles, policy-as-code, simulations, and harmonized reports.
  </div>
  <div class="subsec">
    <p style="font-size:.82rem;color:var(--t2);line-height:1.75">{esc(DATA['executiveSummary'])}</p>
  </div>
  <div class="callout blue">
    <strong>Regulatory Coverage.</strong>
    {render_list(meta['regulatoryCoverage'][:8])}
    <em style="color:var(--t3);font-size:.72rem">+ {len(meta['regulatoryCoverage'])-8} additional instruments documented</em>
  </div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# SUBJECT SYSTEM CARD
# ─────────────────────────────────────────────────────────────────────────────
risk_tier_rows = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in subj['riskTier'].items())
subject_html = f"""
<section id="subject">
  <div class="sh">
    <h2>Subject System — CRS-UUID-001</h2>
    <span class="sb">SUBJECT</span>
    <span class="badge bg-cyan">Tier-1</span>
    <span class="badge bg-red">EU AI Act Annex III §5(b)</span>
    <span class="badge bg-amber">GDPR Art. 22 ADM</span>
  </div>
  <div class="subject-card">
    <h3>🏦 {esc(subj['modelName'])}</h3>
    <dl class="subject-kv">
      <dt>Model ID</dt><dd class="mn" style="color:var(--cyan)">{esc(subj['modelId'])}</dd>
      <dt>Owner</dt><dd>{esc(subj['owner'])}</dd>
      <dt>Purpose</dt><dd>{esc(subj['purpose'])}</dd>
      <dt>Architecture</dt><dd>{esc(subj['architecture'])}</dd>
      <dt>Training Data</dt><dd>{esc(subj['trainingData'])}</dd>
      <dt>Autonomy</dt><dd>{esc(subj['autonomyLevel'])}</dd>
      <dt>Population Impact</dt><dd><strong>{esc(subj['populationImpact'])}</strong></dd>
      <dt>Materiality</dt><dd>{esc(subj['materiality'])}</dd>
    </dl>
    <h4 style="margin-top:1rem;font-size:.85rem;color:var(--amber);font-weight:700">Risk-Tier Classification</h4>
    <dl class="subject-kv" style="margin-top:.4rem">
      {risk_tier_rows}
    </dl>
  </div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# LAYER RENDERING
# ─────────────────────────────────────────────────────────────────────────────
def render_layer_l1():
    L = DATA["L1_institutional"]
    roles = L["roles"]
    lod = roles["lineOfDefence"]
    committees = roles["committees"]
    raci = roles["raci"]
    aims = L["aimsLifecycle"]
    sr117 = L["sr117Mapping"]
    conduct = L["conductControls"]
    kris = L["kris"]

    lod_cards = ""
    for tier, members in lod.items():
        lod_cards += f"""<div class="card"><span class="code">{esc(tier)}</span>
<h3>{esc(tier)}</h3>{render_list(members)}</div>"""

    conduct_cards = ""
    for name, content in conduct.items():
        kv = render_kv(content)
        conduct_cards += f"""<div class="card"><span class="code">{esc(name)}</span>
<h3>{esc(name.replace('_',' '))}</h3>{kv}</div>"""

    return f"""
<section id="L1">
  <div class="sh">
    <h2>L1 · Institutional Governance — Bank-Internal Controls</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-green">Three Lines of Defence</span>
    <span class="badge bg-blue">SR 11-7</span>
    <span class="badge bg-purple">ISO/IEC 42001</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L1.1</span>Three Lines of Defence</h4>
    <div class="g3">{lod_cards}</div>
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.2</span>Governance Committees</h4>
    {render_dict_list(committees, [("name","Committee"),("cadence","Cadence"),("chair","Chair"),("quorum","Quorum"),("crsItem","CRS Agenda")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.3</span>RACI Matrix (CRS-UUID-001 activities)</h4>
    {render_dict_list(raci, [("activity","Activity"),("R","R"),("A","A"),("C","C"),("I","I")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.4</span>ISO/IEC 42001 AIMS Lifecycle — {esc(aims['standard'])}</h4>
    {render_dict_list(aims['stages'], [("stage","Stage"),("crsArtefacts","CRS Artefacts")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.5</span>SR 11-7 Mapping</h4>
    {render_dict_list(sr117, [("section","SR 11-7"),("crsControl","CRS Control"),("owner","Owner")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.6</span>Conduct Controls (FCRA · ECOA · GDPR · Consumer Duty)</h4>
    <div class="g2">{conduct_cards}</div>
  </div>

  <div class="subsec">
    <h4><span class="sid">L1.7</span>KRI Dashboard (live indicators)</h4>
    {render_dict_list(kris, [("kri","KRI"),("threshold","Threshold"),("current","Current"),("status","Status")])}
  </div>
</section>
"""


def render_layer_l2():
    L = DATA["L2_systemic"]
    sup = L["supervisors"]
    icaap = L["icaapCapitalImpact"]
    college = L["supervisoryCollege"]
    hsrs = L["harmonizedSupervisoryReports"]
    replay = L["supervisoryReplayKit"]

    return f"""
<section id="L2">
  <div class="sh">
    <h2>L2 · Systemic Governance — Sectoral & National Supervisors</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-blue">PRA · FCA · OCC · Fed · ECB</span>
    <span class="badge bg-amber">ICAAP Pillar-2</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L2.1</span>Supervisory Authorities</h4>
    {render_dict_list(sup, [("authority","Authority"),("jurisdiction","Jurisdiction"),("primaryInstrument","Primary Instrument"),("crsContactCadence","Cadence")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L2.2</span>ICAAP Capital Impact (Pillar-2 model risk)</h4>
    <div class="g2">
      <div class="card"><h3>Model-Risk Pillar-2 Add-on</h3>{render_kv(icaap['modelRiskPillar2Addon'])}</div>
      <div class="card"><h3>RWA Influence</h3>{render_kv(icaap['rwaInfluenceTable'])}</div>
    </div>
    <h4 style="margin-top:.8rem;font-size:.8rem;color:var(--amber)">Stress Scenarios</h4>
    {render_dict_list(icaap['stressScenarios'], [("scenario","Scenario"),("crsModelSensitivity","CRS Sensitivity"),("capitalImpact","Capital Impact"),("commentary","Commentary")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L2.3</span>Supervisory College</h4>
    <div class="callout">
      <strong>{esc(college['name'])}</strong><br>
      Frequency: {esc(college['frequency'])}<br>
      Participants: {esc(', '.join(college['participants']))}
    </div>
    <h4 style="margin-top:.5rem;font-size:.8rem">Standing Agenda</h4>
    {render_list(college['standingAgenda'])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L2.4</span>Harmonized Global Supervisory Reports</h4>
    {render_dict_list(hsrs, [("reportId","ID"),("title","Report"),("audience","Audience"),("frequency","Frequency"),("format","Format")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L2.5</span>Supervisory Replay Kit</h4>
    <p class="content" style="font-size:.8rem;color:var(--t2);line-height:1.7">{esc(replay['purpose'])}</p>
    <h4 style="font-size:.8rem">Components</h4>{render_list(replay['components'])}
    <div class="callout green" style="margin-top:.5rem"><strong>SLA.</strong> {esc(replay['slaToReproduce'])}</div>
  </div>
</section>
"""


def render_layer_l3():
    L = DATA["L3_frontierCompute"]
    reg = L["computeRegister"]
    ks = L["killSwitch"]
    wc = L["weightCustody"]
    gpu = L["gpuAttestations"]

    return f"""
<section id="L3">
  <div class="sh">
    <h2>L3 · Frontier Compute Governance</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-indigo">Training Register</span>
    <span class="badge bg-red">Kill-Switch ≤60s</span>
    <span class="badge bg-amber">HSM Custody</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L3.1</span>Compute Register (CRS entry)</h4>
    {render_kv(reg['crsEntry'])}
    <div class="callout blue" style="margin-top:.5rem"><strong>Frontier threshold policy.</strong> {esc(reg['frontierThresholdPolicy'])}</div>
  </div>

  <div class="subsec">
    <h4><span class="sid">L3.2</span>Kill-Switch Patterns</h4>
    {render_dict_list(ks['patterns'], [("pattern","Pattern"),("target","Target SLA"),("crsImplementation","CRS Implementation")])}
    <h4 style="margin-top:.7rem;font-size:.8rem">Invocation Authority</h4>
    {render_kv(ks['invocationAuthority'])}
    <h4 style="margin-top:.7rem;font-size:.8rem">Post-Kill Protocol</h4>
    {render_list(ks['postKillProtocol'])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L3.3</span>Weight Custody (HSM + n-of-m escrow)</h4>
    {render_kv(wc)}
  </div>

  <div class="subsec">
    <h4><span class="sid">L3.4</span>GPU/TEE Attestations</h4>
    {render_kv(gpu)}
  </div>
</section>
"""


def render_layer_l4():
    L = DATA["L4_geopoliticalTreaty"]
    gg = L["gagcot"]
    reg = L["crsTreatyRegistration"]
    gcs = L["gcScenarios"]
    runbook = L["crisisRunbooks"]["GC4_runbook"]

    gc_cards = ""
    for gc in gcs:
        gc_cards += f"""<div class="gc-card">
<span class="gc-id">{esc(gc['id'])}</span>
<h3 style="font-size:.9rem;font-weight:700;margin-bottom:.3rem">{esc(gc['name'])}</h3>
<p><strong>Trigger:</strong> {esc(gc['trigger'])}</p>
<p><strong style="color:var(--cyan)">CRS relevance:</strong> {esc(gc['crsRelevance'])}</p>
<p><strong style="color:var(--amber)">MTTR:</strong> <span class="mn" style="color:var(--t1)">{esc(gc['mttr'])}</span></p>
<details><summary style="cursor:pointer;font-size:.72rem;color:var(--t3);margin-top:.4rem">Actions</summary>
{render_list(gc['actions'])}
</details>
</div>"""

    articles = render_dict_list(gg['articles'], [("article","Art."),("title","Title"),("essence","Essence")])
    pillars = render_dict_list(gg['implementationCharter']['pillars'], [("pillar","Pillar"),("function","Function")])
    kpis = render_dict_list(gg['implementationCharter']['kpis'], [("kpi","KPI"),("target","Target"),("measure","Measure")])

    return f"""
<section id="L4">
  <div class="sh">
    <h2>L4 · Geopolitical Treaty Governance — GAGCOT & GC1-GC7</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-purple">Treaty-Level</span>
    <span class="badge bg-red">GC1-GC7</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L4.1</span>GAGCOT Charter — {esc(gg['fullName'])}</h4>
    <div class="callout purple">
      <strong>Authority:</strong> {esc(gg['authority'])}<br>
      <strong>Acronym:</strong> {esc(gg['acronym'])}
    </div>
    <h4 style="margin-top:.5rem;font-size:.8rem">12 Treaty Articles</h4>
    {articles}
  </div>

  <div class="subsec">
    <h4><span class="sid">L4.2</span>CRS Treaty Registration</h4>
    {render_kv({k: v for k, v in reg.items() if k not in ('obligations','entitlements')})}
    <div class="g2" style="margin-top:.5rem">
      <div class="card"><h3 style="color:var(--red)">Obligations</h3>{render_list(reg['obligations'])}</div>
      <div class="card"><h3 style="color:var(--green)">Entitlements</h3>{render_list(reg['entitlements'])}</div>
    </div>
  </div>

  <div class="subsec">
    <h4><span class="sid">L4.3</span>GC1-GC7 Crisis Scenarios</h4>
    <div class="g3">{gc_cards}</div>
  </div>

  <div class="subsec">
    <h4><span class="sid">L4.4</span>GC4 Runbook — CRS Adversarial Data-Poisoning Response</h4>
    <p class="content">{esc(runbook['title'])}</p>
    {render_dict_list(runbook['phases'], [("phase","Phase"),("actions","Actions")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L4.5</span>Treaty Authority Implementation Charter (G-AGCOTA)</h4>
    <p class="content">{esc(gg['implementationCharter']['title'])}</p>
    {pillars}
    <h4 style="margin-top:.7rem;font-size:.8rem;color:var(--amber)">Funding & Staffing</h4>
    <div class="callout"><strong>Funding:</strong> {esc(gg['implementationCharter']['funding'])}<br>
    <strong>Staffing:</strong> {esc(gg['implementationCharter']['staffing'])}<br>
    <strong>Location:</strong> {esc(gg['implementationCharter']['location'])}</div>
    <h4 style="margin-top:.7rem;font-size:.8rem">Authority KPIs</h4>
    {kpis}
  </div>
</section>
"""


def render_layer_l5():
    L = DATA["L5_autonomousMesh"]
    arch = L["meshArchitecture"]
    policies = L["opaPolicies"]
    gates = L["ciCdGates"]
    bundles = L["evidenceBundles"]

    return f"""
<section id="L5">
  <div class="sh">
    <h2>L5 · Autonomous Governance Mesh — Policy-as-Code & Cryptographic Evidence</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-cyan">OPA/Rego</span>
    <span class="badge bg-emerald">CI/CD</span>
    <span class="badge bg-gold">Merkle-Anchored</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L5.1</span>Mesh Architecture</h4>
    {render_kv(arch)}
  </div>

  <div class="subsec">
    <h4><span class="sid">L5.2</span>OPA/Rego Policies (12)</h4>
    {render_dict_list(policies, [("id","ID"),("package","Package"),("title","Title"),("enforces","Enforces"),("decision","Decision")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L5.3</span>CI/CD + Runtime Gates (14)</h4>
    {render_dict_list(gates, [("gate","Gate"),("stage","Stage"),("policy","Policy"),("effect","Effect")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L5.4</span>Cryptographic Evidence Bundles (9)</h4>
    {render_dict_list(bundles, [("id","ID"),("label","Label"),("contents","Contents"),("merkleRoot","Merkle Root"),("retention","Retention")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L5.5</span>Evidence Manifest Schema</h4>
    <pre class="code">{esc(json.dumps(L['evidenceManifestSchema'], indent=2))}</pre>
  </div>
</section>
"""


def render_layer_l6():
    L = DATA["L6_adversarialCoEvo"]
    rt = L["redTeamProgramme"]
    kc = L["killChainTaxonomy"]
    ti = L["threatIntelIntegration"]
    pt = L["purpleTeamLoops"]
    met = L["coEvolutionMetrics"]

    return f"""
<section id="L6">
  <div class="sh">
    <h2>L6 · Adversarial Co-Evolution — Red-Team · Threat Intel · Kill-Chain</h2>
    <span class="sb">{esc(L['id'])}</span>
    <span class="badge bg-red">Red-Team</span>
    <span class="badge bg-amber">MITRE ATLAS</span>
    <span class="badge bg-cyan">Purple-Team</span>
  </div>
  <p class="sd">{esc(L['summary'])}</p>

  <div class="subsec">
    <h4><span class="sid">L6.1</span>Red-Team Programme</h4>
    <div class="callout"><strong>Cadence:</strong> {esc(rt['cadence'])}<br><strong>Independence:</strong> {esc(rt['independence'])}</div>
    <h4 style="margin-top:.5rem;font-size:.8rem">Scope</h4>
    {render_list(rt['scope'])}
    <h4 style="margin-top:.5rem;font-size:.8rem">YTD {esc(rt['findingsSeverity']['ytd'])} Findings by Severity</h4>
    {render_kv({k: v for k, v in rt['findingsSeverity'].items() if k != 'ytd'})}
  </div>

  <div class="subsec">
    <h4><span class="sid">L6.2</span>Kill-Chain Taxonomy (aligned: {esc(kc['aligned'])})</h4>
    {render_dict_list(kc['phases'], [("phase","Phase"),("crsExample","CRS Example")])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L6.3</span>Threat-Intel Integration</h4>
    <h4 style="font-size:.78rem">Feeds</h4>{render_list(ti['feeds'])}
    <p class="content" style="margin-top:.5rem"><strong>Engine:</strong> {esc(ti['correlationEngine'])}</p>
    <p class="content"><strong>Sharing Protocol:</strong> {esc(ti['sharingProtocol'])}</p>
  </div>

  <div class="subsec">
    <h4><span class="sid">L6.4</span>Purple-Team Loops</h4>
    <div class="callout green"><strong>Frequency:</strong> {esc(pt['frequency'])}</div>
    <h4 style="font-size:.78rem">Outputs</h4>{render_list(pt['outputs'])}
  </div>

  <div class="subsec">
    <h4><span class="sid">L6.5</span>Co-Evolution Metrics</h4>
    {render_dict_list(met, [("metric","Metric"),("target","Target"),("current","Current")])}
  </div>
</section>
"""


# ─────────────────────────────────────────────────────────────────────────────
# ANNEX IV DOSSIER
# ─────────────────────────────────────────────────────────────────────────────
annex = DATA["L1_institutional"]["annexIvDossier"]
annex_html = f"""
<section id="annexiv">
  <div class="sh">
    <h2>EU AI Act Annex IV — Technical Documentation Dossier</h2>
    <span class="sb">ANNEX-IV</span>
    <span class="badge bg-red">High-Risk</span>
    <span class="badge bg-blue">Notified-Body Ready</span>
  </div>
  <p class="sd">{esc(annex['instrument'])} · Document ID <code class='mn' style='color:var(--cyan)'>{esc(annex['doc'])}</code> · {esc(annex['sizing'])}</p>
  {render_dict_list(annex['structure'], [("section","Section"),("crsContent","CRS Content"),("evidenceBundle","Evidence Bundle")])}
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# CAPITAL IMPACT
# ─────────────────────────────────────────────────────────────────────────────
ci = DATA["capitalImpactAssessment"]
capital_html = f"""
<section id="capital">
  <div class="sh">
    <h2>Capital Impact Assessment — ICAAP Pillar-2</h2>
    <span class="sb">CAPITAL</span>
    <span class="badge bg-amber">Basel III</span>
    <span class="badge bg-blue">PRA SS1/23</span>
  </div>
  <p class="sd">{esc(ci['title'])} · Framework: {esc(ci['framework'])}</p>
  <div class="g2">
    <div class="card"><h3>Base Case</h3>{render_kv(ci['baseCase'])}</div>
    <div class="card"><h3>Assurance Depth Uplift (post-WP-032)</h3>{render_kv(ci['assuranceDepthUplift'])}</div>
  </div>
  <h4 style="margin-top:.8rem;font-size:.85rem;color:var(--amber)">Scenario Capital Sensitivity</h4>
  {render_dict_list(ci['scenarioCapitalSensitivity'], [("scenario","Scenario"),("crsModelSensitivity","CRS Sensitivity"),("capitalImpact","Capital Impact"),("commentary","Commentary")])}
  <div class="callout gold" style="margin-top:.8rem"><strong>Board Conclusion.</strong> {esc(ci['boardConclusion'])}</div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION REPORT
# ─────────────────────────────────────────────────────────────────────────────
vr = DATA["validationReport"]
validation_html = f"""
<section id="validation">
  <div class="sh">
    <h2>Independent Model Validation (IMV) Report</h2>
    <span class="sb">IMV</span>
    <span class="badge bg-green">SR 11-7 §IV</span>
    <span class="badge bg-blue">PRA SS1/23</span>
  </div>
  <p class="sd">{esc(vr['title'])} · Authority: {esc(vr['authority'])} · Issued: {esc(vr['dateIssued'])} · Scope: {esc(vr['scope'])}</p>
  <div class="g2">
    <div class="card"><h3>Findings by Severity</h3>{render_kv(vr['findings'])}</div>
    <div class="card"><h3>Conclusions</h3>{render_list(vr['conclusions'])}</div>
  </div>
  <div class="subsec">
    <h4><span class="sid">IMV.1</span>Effective-Challenge Examples</h4>
    {render_list(vr['effectiveChallengeExamples'])}
  </div>
  <div class="subsec">
    <h4><span class="sid">IMV.2</span>Recommendations</h4>
    {render_list(vr['recommendations'])}
  </div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# SIMULATIONS
# ─────────────────────────────────────────────────────────────────────────────
sims_html = f"""
<section id="simulations">
  <div class="sh">
    <h2>Multi-Layer Simulations (13 Scenarios)</h2>
    <span class="sb">SIMS</span>
    <span class="badge bg-purple">Layer-Spanning</span>
    <span class="badge bg-red">Incl. GC1-GC7</span>
  </div>
  <p class="sd">Regulator-observable simulations validating the entire stack end-to-end: institutional escalation, systemic supervisory coordination, frontier-compute kill-switch, treaty-level crisis response, policy-as-code chaos, and adversarial co-evolution.</p>
  {render_dict_list(DATA['simulations'], [("id","ID"),("layer","Layer"),("name","Simulation"),("objective","Objective"),("kpis","KPIs"),("passCriteria","Pass Criteria")])}
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────
schema_cards = []
for name, schema in DATA["schemas"].items():
    pretty = json.dumps(schema, indent=2, ensure_ascii=False)
    if len(pretty) > 1900:
        pretty = pretty[:1900] + "\n... [truncated; full via /api/civ-ai-gov-6l/schemas/" + name + "]"
    schema_cards.append(f"""<div class="card">
<span class="code">{esc(name)}</span>
<h3>{esc(schema.get('$id','').split('/')[-1] or name)}</h3>
<p>JSON Schema — {esc(schema.get('$schema','draft'))}</p>
<pre class="code">{esc(pretty)}</pre>
</div>""")
schemas_html = f"""
<section id="schemas">
  <div class="sh">
    <h2>JSON Schemas (5)</h2>
    <span class="sb">SCHEMAS</span>
    <span class="badge bg-blue">Wire-Level</span>
  </div>
  <p class="sd">Authoritative JSON Schemas for evidence manifests, compute-register entries, harmonized supervisory reports, supervisory replay requests, and GC activation records.</p>
  <div class="g2">{"".join(schema_cards)}</div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# CODE EXAMPLES
# ─────────────────────────────────────────────────────────────────────────────
code_lang = {
    "regoAnnexIvGate":      ("Rego / OPA",      "P-001 · Annex IV completeness gate"),
    "regoFairnessGate":     ("Rego / OPA",      "P-002 · 4/5 rule fairness gate"),
    "killSwitchProcedure":  ("Shell",           "Kill-switch procedure (operator-facing)"),
    "evidenceManifestExample": ("JSON",         "EB-005 evidence manifest (signed, Merkle-anchored)"),
    "harmonizedReportExample": ("JSON",         "HSR-01 Quarterly Supervisory Summary (signed)"),
    "computeRegisterYaml":  ("YAML",            "Compute register entry (CRS training run)"),
}
code_cards = []
for name, code in DATA["codeExamples"].items():
    lang, desc = code_lang.get(name, ("text", ""))
    if len(code) > 2800:
        code = code[:2800] + "\n# ... [truncated]"
    code_cards.append(f"""<div class="card">
<span class="code">{esc(name)}</span>
<h3>{esc(desc)}</h3>
<div class="badge bg-cyan">{esc(lang)}</div>
<pre class="code">{esc(code)}</pre>
</div>""")
code_html = f"""
<section id="code">
  <div class="sh">
    <h2>Reference Code Examples (6)</h2>
    <span class="sb">CODE</span>
    <span class="badge bg-indigo">Reference Implementation</span>
  </div>
  <p class="sd">Production-oriented reference implementations covering OPA/Rego policy-as-code (Annex IV + fairness), kill-switch procedure, evidence manifest, harmonized report, and compute-register entry.</p>
  <div class="g2">{"".join(code_cards)}</div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────
api_rows = [
    ("GET", "/api/civ-ai-gov-6l",                    "Full blueprint"),
    ("GET", "/api/civ-ai-gov-6l/meta",               "Metadata"),
    ("GET", "/api/civ-ai-gov-6l/summary",            "Aggregate counts"),
    ("GET", "/api/civ-ai-gov-6l/executive-summary",  "Executive summary (text/plain)"),
    ("GET", "/api/civ-ai-gov-6l/subject",            "Subject system (CRS-UUID-001)"),
    ("GET", "/api/civ-ai-gov-6l/layers",             "All 6 layers (summary)"),
    ("GET", "/api/civ-ai-gov-6l/l1 … l6",            "Individual layer"),
    ("GET", "/api/civ-ai-gov-6l/l1/kris",            "L1 KRI dashboard"),
    ("GET", "/api/civ-ai-gov-6l/l1/annex-iv",        "Annex IV dossier"),
    ("GET", "/api/civ-ai-gov-6l/l1/sr11-7",          "SR 11-7 mapping"),
    ("GET", "/api/civ-ai-gov-6l/l1/conduct",         "FCRA · ECOA · GDPR · Consumer Duty"),
    ("GET", "/api/civ-ai-gov-6l/l2/icaap",           "ICAAP capital impact"),
    ("GET", "/api/civ-ai-gov-6l/l2/college",         "Supervisory college"),
    ("GET", "/api/civ-ai-gov-6l/l2/hsr",             "Harmonized supervisory reports"),
    ("GET", "/api/civ-ai-gov-6l/l2/hsr/:id",         "Specific HSR (HSR-01..HSR-08)"),
    ("GET", "/api/civ-ai-gov-6l/l2/replay-kit",      "Supervisory replay kit"),
    ("GET", "/api/civ-ai-gov-6l/l3/compute-register","Compute register entry"),
    ("GET", "/api/civ-ai-gov-6l/l3/kill-switch",     "Kill-switch patterns"),
    ("GET", "/api/civ-ai-gov-6l/l3/weight-custody",  "HSM weight custody"),
    ("GET", "/api/civ-ai-gov-6l/l4/gagcot",          "GAGCOT treaty charter"),
    ("GET", "/api/civ-ai-gov-6l/l4/articles",        "12 treaty articles"),
    ("GET", "/api/civ-ai-gov-6l/l4/articles/:id",    "Specific article"),
    ("GET", "/api/civ-ai-gov-6l/l4/implementation-charter","G-AGCOTA charter"),
    ("GET", "/api/civ-ai-gov-6l/l4/gc",              "GC1-GC7 scenarios"),
    ("GET", "/api/civ-ai-gov-6l/l4/gc/:id",          "Specific GC scenario"),
    ("GET", "/api/civ-ai-gov-6l/l4/gc4-runbook",     "GC4 runbook (CRS)"),
    ("GET", "/api/civ-ai-gov-6l/l5/opa-policies",    "12 OPA/Rego policies"),
    ("GET", "/api/civ-ai-gov-6l/l5/opa-policies/:id","Specific policy (P-001..P-012)"),
    ("GET", "/api/civ-ai-gov-6l/l5/ci-cd-gates",     "14 CI/CD gates"),
    ("GET", "/api/civ-ai-gov-6l/l5/evidence-bundles","9 evidence bundles"),
    ("GET", "/api/civ-ai-gov-6l/l5/evidence-bundles/:id","Specific bundle (EB-001..EB-009)"),
    ("GET", "/api/civ-ai-gov-6l/l6/red-team",        "Red-team programme"),
    ("GET", "/api/civ-ai-gov-6l/l6/kill-chain",      "Kill-chain taxonomy"),
    ("GET", "/api/civ-ai-gov-6l/l6/threat-intel",    "Threat-intel integration"),
    ("GET", "/api/civ-ai-gov-6l/simulations",        "13 multi-layer simulations"),
    ("GET", "/api/civ-ai-gov-6l/simulations/:id",    "Specific simulation"),
    ("GET", "/api/civ-ai-gov-6l/capital-impact",     "ICAAP Pillar-2 assessment"),
    ("GET", "/api/civ-ai-gov-6l/validation-report",  "IMV report"),
    ("GET", "/api/civ-ai-gov-6l/schemas",            "JSON schemas"),
    ("GET", "/api/civ-ai-gov-6l/schemas/:name",      "Specific schema"),
    ("GET", "/api/civ-ai-gov-6l/code-examples",      "Reference code examples"),
    ("GET", "/api/civ-ai-gov-6l/code-examples/:name","Specific code example"),
]
api_rows_html = "".join(
    f"<tr><td><span class='badge bg-green'>{esc(m)}</span></td>"
    f"<td><code class='mn' style='color:var(--cyan)'>{esc(path)}</code></td>"
    f"<td>{esc(desc)}</td></tr>" for m, path, desc in api_rows
)
api_html = f"""
<section id="api">
  <div class="sh">
    <h2>API Endpoints (70+)</h2>
    <span class="sb">API</span>
    <span class="badge bg-green">Live</span>
    <span class="badge bg-purple">JSON</span>
  </div>
  <p class="sd">All endpoints return JSON (except <code class='mn'>/executive-summary</code> which is text/plain). Every layer, artefact, policy, gate, bundle, scenario, and simulation is individually addressable.</p>
  <div class="tc"><table id="api-list">
    <thead><tr><th>Method</th><th>Path</th><th>Purpose</th></tr></thead>
    <tbody>{api_rows_html}</tbody>
  </table></div>
</section>
"""

# ─────────────────────────────────────────────────────────────────────────────
# ASSEMBLE
# ─────────────────────────────────────────────────────────────────────────────
FOOTER = f"""
<div class="footer">
  <p>{esc(meta['docRef'])} · v{esc(meta['version'])} · {esc(meta['date'])} · Classification: {esc(meta['classification'])}</p>
  <p>Six-Layer Civilizational AI Governance Blueprint · CRS-UUID-001 Reference Implementation · <a href="/governance-hub.html">Governance Hub</a> · <a href="/ent-ai-gov-blueprint.html">Enterprise Blueprint (WP-030)</a> · <a href="/civ-ai-gov-stack.html">Civilizational Stack (WP-031)</a></p>
  <p style="margin-top:.3rem">Aligned with EU AI Act (Annex IV) · SR 11-7 · Basel III/ICAAP · ISO/IEC 42001 · GDPR · FCRA/ECOA · GAGCOT GC1-GC7</p>
</div>
"""

HTML = (HEAD + HERO + NAV + '<main id="main">' + exec_html + subject_html
        + render_layer_l1() + render_layer_l2() + render_layer_l3()
        + render_layer_l4() + render_layer_l5() + render_layer_l6()
        + annex_html + capital_html + validation_html + sims_html
        + schemas_html + code_html + api_html + '</main>' + FOOTER + """
<script>
const sections=document.querySelectorAll('main section[id]');
const navLinks=document.querySelectorAll('nav.sn a[href^="#"]');
const io=new IntersectionObserver((entries)=>{entries.forEach(e=>{if(e.isIntersecting){const id=e.target.id;navLinks.forEach(a=>a.classList.toggle('active',a.getAttribute('href')==='#'+id))}})},{rootMargin:'-40% 0px -55% 0px'});
sections.forEach(s=>io.observe(s));
</script>
</body></html>""")

OUT.write_text(HTML, encoding="utf-8")
print(f"Wrote {OUT} ({OUT.stat().st_size // 1024} KB, {HTML.count(chr(10))+1} lines)")
print(f"Layers rendered: 6 | Sections: {len(nav_sections)}")
