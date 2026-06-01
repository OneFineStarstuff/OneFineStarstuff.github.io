#!/usr/bin/env python3
"""WP-054 — CIV-AI-GOVERNANCE-IMPL-BLUEPRINT HTML dashboard renderer."""
import json, html
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "civ-ai-governance-impl-blueprint.json"
OUT = ROOT / "public" / "civ-ai-governance-impl-blueprint.html"

D = json.loads(SRC.read_text())


def esc(s):
    return html.escape(str(s)) if s is not None else ""


def render_value(v):
    if isinstance(v, dict):
        return render_kv(v)
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return "<ol>" + "".join(f"<li>{render_kv(x)}</li>" for x in v) + "</ol>"
        return "<ul>" + "".join(f"<li>{esc(i)}</li>" for i in v) + "</ul>"
    return esc(v)


def render_kv(d):
    if not isinstance(d, dict):
        return esc(d)
    return "<table class='kv'>" + "".join(
        f"<tr><th>{esc(k)}</th><td>{render_value(v)}</td></tr>" for k, v in d.items()
    ) + "</table>"


def render_list(items):
    return "<ul>" + "".join(f"<li>{render_value(i)}</li>" for i in (items or [])) + "</ul>"


# Modules
mods_html = []
for m in D["modules"]:
    secs = []
    for s in m["sections"]:
        body_html = render_value(s.get("content"))
        secs.append(
            f"<details class='sec'><summary><b>{esc(s['id'])}</b> — {esc(s['title'])}</summary>{body_html}</details>"
        )
    covers = ""
    if m.get("covers"):
        covers = "<div class='covers'>" + "".join(
            f"<span class='pill'>{esc(c)}</span>" for c in m["covers"]
        ) + "</div>"
    mods_html.append(f"""
    <article class='module' id='{esc(m['id'])}'>
      <h3>{esc(m['title'])}</h3>
      <p class='summary'>{esc(m.get('summary',''))}</p>
      {covers}
      {''.join(secs)}
    </article>""")

# Common tables
kpi_rows = "".join(
    f"<tr><td>{esc(k['id'])}</td><td>{esc(k['name'])}</td><td><b>{esc(k['target'])}</b></td><td>{esc(k.get('frequency',''))}</td><td>{esc(k.get('owner',''))}</td></tr>"
    for k in D["kpis"]
)
reg_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['name'])}</td><td>{esc(r.get('regime',''))}</td><td>{esc(', '.join(r.get('submissions',[])))}</td></tr>"
    for r in D["regulators"]
)
df_rows = "".join(
    f"<tr><td>{esc(d['id'])}</td><td>{esc(d['name'])}</td><td>{esc(d.get('from',''))} → {esc(d.get('to',''))}</td><td>{esc(', '.join(d.get('controls',[])))}</td><td>{esc(d.get('wormTopic',''))}</td></tr>"
    for d in D["dataFlows"]
)
trace_rows = "".join(
    f"<tr><td>{esc(t['id'])}</td><td>{esc(t['requirement'])}</td><td>{esc(t.get('module',''))}</td><td>{esc(t.get('control',''))}</td><td>{esc(t.get('evidence',''))}</td></tr>"
    for t in D["traceability"]
)
rc_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['risk'])}</td><td>{esc(r.get('inherent',''))}</td><td>{esc(', '.join(r.get('controls',[])))}</td><td>{esc(r.get('residual',''))}</td><td>{esc(r.get('owner',''))}</td></tr>"
    for r in D["riskControlMatrix"]
)
schema_rows = "".join(
    f"<tr><td>{esc(s['id'])}</td><td>{esc(s['name'])}</td><td>{esc(s.get('purpose',''))}</td><td>{esc(', '.join(s['fields']))}</td></tr>"
    for s in D["schemas"]
)
code_html = "".join(
    f"<details class='code'><summary><b>{esc(c['id'])}</b> — {esc(c['title'])} <i>({esc(c['lang'])})</i></summary><pre>{esc(c['snippet'])}</pre></details>"
    for c in D["code"]
)
rollout_rows = "".join(
    f"<tr><td>{esc(r['phase'])}</td><td>{render_value(r.get('deliverables',[]))}</td><td>{esc(r.get('exitGate',''))}</td></tr>"
    for r in D["rollout90"]
)
roadmap_rows = "".join(
    f"<tr><td>{esc(r['year'])}</td><td>{render_value(r.get('themes',[]))}</td><td>{esc(', '.join(r.get('gates',[])))}</td></tr>"
    for r in D["roadmap"]
)

# Distinctive WP-054 — 9 sections
# S1: roadmapMilestones
ms_rows = "".join(
    f"<tr><td>{esc(m['id'])}</td><td>{esc(m['name'])}</td><td>{esc(m['quarter'])}</td>"
    f"<td>{esc(', '.join(m.get('dependsOn',[])) or '—')}</td>"
    f"<td>{render_value(m.get('deliverables',[]))}</td>"
    f"<td>{esc(m.get('owner',''))}</td>"
    f"<td>{esc(', '.join(m.get('regimes',[])))}</td></tr>"
    for m in D["roadmapMilestones"]
)
# S3: productFeatures
pf_html = "".join(
    f"<details class='code' id='{esc(f['id'])}'><summary><b>{esc(f['id'])}</b> — {esc(f['name'])} <i>({esc(f.get('kind',''))})</i></summary>"
    f"<p class='summary'><b>Surface:</b> {esc(f.get('surface',''))} · <b>Telemetry:</b> <code>{esc(f.get('telemetry',''))}</code></p>"
    f"<h5>Capabilities</h5>{render_list(f.get('capabilities',[]))}"
    f"</details>"
    for f in D["productFeatures"]
)
# S2: safetySections
saf_html = "".join(
    f"<details class='code' id='{esc(s['id'])}'><summary><b>{esc(s['id'])}</b> — {esc(s['category'])}</summary>"
    f"<h5>Examples</h5>{render_list(s.get('examples',[]))}"
    f"<h5>Mitigations</h5>{render_list(s.get('mitigations',[]))}"
    f"<h5>Stakeholders</h5>{render_list(s.get('stakeholders',[]))}"
    f"</details>"
    for s in D["safetySections"]
)
# S4: reportSections
rpt_html = "".join(
    f"<details class='code' id='{esc(r['id'])}'><summary><b>{esc(r['id'])}</b> — {esc(r['title'])} <i>({esc(r['audience'])} · {esc(r.get('lengthWords','-'))} words)</i></summary>"
    f"<h5>Sections</h5>{render_list(r.get('sections',[]))}"
    f"</details>"
    for r in D["reportSections"]
)
# S5: promptEngineering — large rich blocks
pe_html_parts = []
for pe in D["promptEngineering"]:
    code_blocks = "".join(
        f"<details><summary>{esc(c['name'])} <i>({esc(c['lang'])})</i></summary><pre>{esc(c['snippet'])}</pre></details>"
        for c in pe.get("codeSnippets", [])
    )
    bench_rows = "".join(
        f"<tr><td>{esc(b['metric'])}</td><td>{esc(b['value'])}</td></tr>"
        for b in pe.get("benchmarks", [])
    )
    pe_html_parts.append(
        f"<details class='code' id='{esc(pe['id'])}'><summary><b>{esc(pe['id'])}</b> — {esc(pe['name'])} <i>(~{esc(pe.get('words','-'))} words)</i></summary>"
        f"<h5>Objectives</h5>{render_list(pe.get('objectives',[]))}"
        f"<h5>Lessons</h5>{render_list(pe.get('lessons',[]))}"
        f"<h5>Code Snippets</h5>{code_blocks}"
        f"<h5>Benchmarks</h5><table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{bench_rows}</tbody></table>"
        f"</details>"
    )
pe_html = "".join(pe_html_parts)
# S6: ninetyDayPack
d90_rows = "".join(
    f"<tr><td>{esc(d['id'])}</td><td>{esc(d['week'])}</td><td><b>{esc(d['name'])}</b></td>"
    f"<td>{render_value(d.get('activities',[]))}</td>"
    f"<td>{esc(d.get('exitGate',''))}</td>"
    f"<td>{esc(d.get('owner',''))}</td></tr>"
    for d in D["ninetyDayPack"]
)
# S7+S8: civilizationalStack
civ_rows = "".join(
    f"<tr><td>{esc(c['id'])}</td><td><b>{esc(c['name'])}</b></td><td>{esc(c.get('scope',''))}</td>"
    f"<td>{esc(', '.join(c.get('components',[])))}</td>"
    f"<td>{esc(', '.join(c.get('regulators',[])))}</td>"
    f"<td>{esc(c.get('horizon',''))}</td></tr>"
    for c in D["civilizationalStack"]
)
# S8: crsCaseStudy
crs_html = "".join(
    f"<details class='code' id='{esc(a['id'])}'><summary><b>{esc(a['id'])}</b> — {esc(a['name'])} <i>({esc(a.get('kind',''))})</i></summary>"
    f"<p class='summary'>{esc(a.get('content',''))}</p>"
    f"<p><b>Regulators:</b> {esc(', '.join(a.get('regulators',[])))}</p>"
    f"<p><b>Evidence:</b> {esc(a.get('evidence',''))}</p>"
    f"</details>"
    for a in D["crsCaseStudy"]
)
# S9: workflowAIPro
wap_html = "".join(
    f"<details class='code' id='{esc(w['id'])}'><summary><b>{esc(w['id'])}</b> — {esc(w['name'])} <i>({esc(w.get('category',''))})</i></summary>"
    f"<p class='summary'>{esc(w.get('description',''))}</p>"
    f"<p><b>SLA:</b> {esc(w.get('sla',''))}</p>"
    f"<p><b>Integrations:</b> {esc(', '.join(w.get('integrations',[])))}</p>"
    f"</details>"
    for w in D["workflowAIPro"]
)

HTML = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{esc(D['title'])} — {esc(D['docRef'])}</title>
<style>
  :root {{ --bg:#0b1220; --panel:#111a2c; --ink:#e6edf7; --muted:#9aa7c2; --accent:#6ea8fe; --good:#34d399; --warn:#fbbf24; --bad:#f87171; }}
  * {{ box-sizing:border-box }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto }}
  header {{ padding:24px 32px; background:linear-gradient(135deg,#0b1220,#152346); border-bottom:1px solid #1c2742 }}
  header h1 {{ margin:0 0 4px; font-size:22px }}
  header .meta {{ color:var(--muted); font-size:12px }}
  nav {{ position:sticky; top:0; background:rgba(11,18,32,.92); backdrop-filter:blur(8px); padding:10px 16px; border-bottom:1px solid #1c2742; z-index:9; display:flex; flex-wrap:wrap; gap:6px }}
  nav a {{ color:var(--accent); text-decoration:none; padding:4px 10px; border-radius:999px; font-size:12px; border:1px solid #1c2742 }}
  nav a:hover {{ background:#162446 }}
  main {{ padding:24px 32px; max-width:1280px; margin:0 auto }}
  section.block {{ background:var(--panel); border:1px solid #1c2742; border-radius:14px; padding:18px 22px; margin:18px 0 }}
  section.block h2 {{ margin:0 0 12px; font-size:18px; color:var(--accent) }}
  table {{ width:100%; border-collapse:collapse; font-size:13px }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1c2742; vertical-align:top }}
  th {{ background:#0e1730; color:var(--muted); font-weight:600 }}
  table.kv {{ font-size:12px }}
  table.kv th {{ width:30%; background:#0a1226 }}
  pre {{ background:#070d1d; color:#cfe2ff; padding:12px; border-radius:10px; overflow:auto; font-size:12px; max-height:420px }}
  .pill {{ display:inline-block; padding:2px 10px; border-radius:999px; background:#162446; color:var(--ink); font-size:11px; margin:2px 4px 2px 0 }}
  details {{ background:#0e1730; border:1px solid #1c2742; border-radius:10px; padding:8px 12px; margin:6px 0 }}
  details summary {{ cursor:pointer; color:var(--ink) }}
  .grid {{ display:grid; gap:14px }}
  .grid.k3 {{ grid-template-columns:repeat(3,1fr) }}
  .grid.k2 {{ grid-template-columns:repeat(2,1fr) }}
  .stat {{ background:#0e1730; border:1px solid #1c2742; border-radius:12px; padding:14px }}
  .stat .v {{ font-size:24px; font-weight:700; color:var(--accent) }}
  .stat .l {{ color:var(--muted); font-size:12px }}
  article.module {{ background:#0e1730; border:1px solid #1c2742; border-radius:12px; padding:14px; margin:10px 0 }}
  article.module h3 {{ margin:0 0 4px; color:var(--ink) }}
  article.module p.summary {{ color:var(--muted); margin:0 0 10px }}
  .covers {{ margin-bottom:8px }}
  .directive pre {{ max-height:280px }}
  footer {{ padding:24px 32px; color:var(--muted); font-size:11px; border-top:1px solid #1c2742 }}
</style>
</head><body>
<header>
  <h1>{esc(D['title'])}</h1>
  <div class='meta'><b>{esc(D['docRef'])}</b> · v{esc(D['version'])} · {esc(D['horizon'])} · {esc(D['classification'])}</div>
  <div class='meta'>Owner: {esc(D['owner'])}</div>
</header>
<nav>
  <a href="#summary">Summary</a>
  <a href="#directive">Directive</a>
  <a href="#modules">Modules</a>
  <a href="#milestones">S1 Milestones</a>
  <a href="#safety">S2 Safety</a>
  <a href="#features">S3 Features</a>
  <a href="#reports">S4 Reports</a>
  <a href="#prompt-eng">S5 Prompt Eng</a>
  <a href="#ninety-day">S6 90-Day</a>
  <a href="#civ-stack">S7+S8 Civ Stack</a>
  <a href="#crs">S8 CRS Case</a>
  <a href="#wap">S9 WorkflowAI</a>
  <a href="#kpis">KPIs</a>
  <a href="#rcm">Risk</a>
  <a href="#regulators">Regulators</a>
  <a href="#dataflows">Data Flows</a>
  <a href="#trace">Traceability</a>
  <a href="#schemas">Schemas</a>
  <a href="#code">Code</a>
  <a href="#roadmap">Roadmap</a>
  <a href="#evidence">Evidence</a>
  <a href="#privacy">Privacy</a>
  <a href="#deploy">Deployment</a>
</nav>
<main>

<section class='block' id='summary'>
  <h2>Executive Summary</h2>
  <p><b>Thesis:</b> {esc(D['executiveSummary'].get('thesis',''))}</p>
  <p><b>Investment range:</b> {esc(D['executiveSummary'].get('investmentRange',''))}</p>
  <h4>Top Risks</h4>
  {render_value(D['executiveSummary'].get('topRisks',[]))}
  <h4>Top Controls</h4>
  {render_value(D['executiveSummary'].get('topControls',[]))}
  <h4>Board Asks</h4>
  {render_value(D['executiveSummary'].get('boardAsks',[]))}
  <h4>Builds On</h4>
  <div>{''.join(f"<span class='pill'>{esc(b)}</span>" for b in D.get('buildsOn',[]))}</div>
  <h4>Counts</h4>
  <div class='grid k3'>
    {''.join(f"<div class='stat'><div class='v'>{v}</div><div class='l'>{esc(k)}</div></div>" for k,v in D['counts'].items())}
  </div>
  <h4>Regimes Aligned</h4>
  <div>{''.join(f"<span class='pill'>{esc(r)}</span>" for r in D.get('regimes',[]))}</div>
</section>

<section class='block directive' id='directive'>
  <h2>Machine-Parsable &lt;directive&gt; Block</h2>
  {render_kv(D.get('directive',{}))}
</section>

<section class='block' id='modules'>
  <h2>Modules ({len(D['modules'])}) — One per Scope Item S1–S9</h2>
  {''.join(mods_html)}
</section>

<section class='block' id='milestones'>
  <h2>S1 — Dependency-Aware Roadmap Milestones ({len(D['roadmapMilestones'])})</h2>
  <p class='summary'>Quarterly milestones MS-26Q1..MS-30Q4 with dependencies, deliverables, owners, and regime mappings.</p>
  <table><thead><tr><th>ID</th><th>Name</th><th>Quarter</th><th>Depends On</th><th>Deliverables</th><th>Owner</th><th>Regimes</th></tr></thead><tbody>{ms_rows}</tbody></table>
</section>

<section class='block' id='safety'>
  <h2>S2 — AI Safety + Governance Sections ({len(D['safetySections'])})</h2>
  <p class='summary'>Risk categories (misuse, unintended, existential) with examples, mitigations, and stakeholder mapping.</p>
  {saf_html}
</section>

<section class='block' id='features'>
  <h2>S3 — Product Features ({len(D['productFeatures'])})</h2>
  <p class='summary'>Model Registry, Prompt UI, Compliance Dashboard, Version Control, PDF Export, Telemetry+PID+Merkle, Active Learning, Cognitive Orchestrator.</p>
  {pf_html}
</section>

<section class='block' id='reports'>
  <h2>S4 — Markdown Report Sections ({len(D['reportSections'])})</h2>
  <p class='summary'>Per-audience report packs for Board, CRO, CAIO, CISO, Regulators (PRA/FCA, OCC/Fed, ECB/EBA), AISI, ICGC, Auditors, Internal Audit, Public Transparency.</p>
  {rpt_html}
</section>

<section class='block' id='prompt-eng'>
  <h2>S5 — Advanced Prompt Engineering Guide ({len(D['promptEngineering'])} modules · ~11k words)</h2>
  <p class='summary'>Foundations, Patterns + Techniques, Tooling/Eval/Benchmarks, Production + Safety, Advanced Frontiers — each with objectives, lessons, code snippets, and benchmarks.</p>
  {pe_html}
</section>

<section class='block' id='ninety-day'>
  <h2>S6 — 90-Day Execution Pack ({len(D['ninetyDayPack'])} weeks)</h2>
  <p class='summary'>Week-by-week activities, exit gates, and owners for the 12-week kick-off.</p>
  <table><thead><tr><th>ID</th><th>Week</th><th>Name</th><th>Activities</th><th>Exit Gate</th><th>Owner</th></tr></thead><tbody>{d90_rows}</tbody></table>
</section>

<section class='block' id='civ-stack'>
  <h2>S7+S8 — Civilizational AI Governance Stack ({len(D['civilizationalStack'])} layers CL1–CL6)</h2>
  <p class='summary'>Sovereign Treaty · Supervisory · Registry · Institutional Governance · Operational Control · Model+Application layers spanning 2026-2050+.</p>
  <table><thead><tr><th>ID</th><th>Layer</th><th>Scope</th><th>Components</th><th>Regulators</th><th>Horizon</th></tr></thead><tbody>{civ_rows}</tbody></table>
</section>

<section class='block' id='crs'>
  <h2>S8 — CRS-UUID-001 Case Study Artifacts ({len(D['crsCaseStudy'])})</h2>
  <p class='summary'>Credit Risk Scoring AI at Global Bank plc — comprehensive deliverables: profile, Annex IV pack, DPIA, FRIA, SR 11-7 validation, ICAAP, FCRA mapping, crisis simulation, crypto evidence manifest, treaty-level reporting.</p>
  {crs_html}
</section>

<section class='block' id='wap'>
  <h2>S9 — WorkflowAI Pro Capabilities ({len(D['workflowAIPro'])})</h2>
  <p class='summary'>BPMN designer, approval orchestration, Sentinel compliance automation, EAIP interop, containment-breach simulation, Cognitive Orchestrator dashboard, active learning, PID alignment tuning, advanced PDF export, RBAC + JIT elevation.</p>
  {wap_html}
</section>

<section class='block' id='kpis'>
  <h2>Supervisory KPIs ({len(D['kpis'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Target</th><th>Frequency</th><th>Owner</th></tr></thead><tbody>{kpi_rows}</tbody></table>
</section>

<section class='block' id='rcm'>
  <h2>Risk &amp; Control Matrix ({len(D['riskControlMatrix'])})</h2>
  <table><thead><tr><th>ID</th><th>Risk</th><th>Inherent</th><th>Controls</th><th>Residual</th><th>Owner</th></tr></thead><tbody>{rc_rows}</tbody></table>
</section>

<section class='block' id='regulators'>
  <h2>Regulators ({len(D['regulators'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Regime</th><th>Submissions</th></tr></thead><tbody>{reg_rows}</tbody></table>
</section>

<section class='block' id='dataflows'>
  <h2>Data Flows ({len(D['dataFlows'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>From → To</th><th>Controls</th><th>WORM Topic</th></tr></thead><tbody>{df_rows}</tbody></table>
</section>

<section class='block' id='trace'>
  <h2>Traceability ({len(D['traceability'])})</h2>
  <table><thead><tr><th>ID</th><th>Requirement</th><th>Module</th><th>Control</th><th>Evidence</th></tr></thead><tbody>{trace_rows}</tbody></table>
</section>

<section class='block' id='schemas'>
  <h2>Schemas ({len(D['schemas'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Purpose</th><th>Fields</th></tr></thead><tbody>{schema_rows}</tbody></table>
</section>

<section class='block' id='code'>
  <h2>Code Examples ({len(D['code'])})</h2>
  {code_html}
</section>

<section class='block' id='roadmap'>
  <h2>30/60/90-Day Rollout + 2026-2030 Roadmap</h2>
  <h3>30/60/90 Day</h3>
  <table><thead><tr><th>Phase</th><th>Deliverables</th><th>Exit Gate</th></tr></thead><tbody>{rollout_rows}</tbody></table>
  <h3>2026-2030 Roadmap ({len(D['roadmap'])} years)</h3>
  <table><thead><tr><th>Year</th><th>Themes</th><th>Gates</th></tr></thead><tbody>{roadmap_rows}</tbody></table>
</section>

<section class='block' id='evidence'>
  <h2>Regulator/Auditor Evidence Pack</h2>
  {render_kv(D['evidencePack'])}
</section>

<section class='block' id='privacy'>
  <h2>Privacy &amp; Sovereignty</h2>
  {render_kv(D['privacy'])}
</section>

<section class='block' id='deploy'>
  <h2>Deployment Considerations</h2>
  {render_kv(D.get('deployment',{}))}
</section>

</main>
<footer>API prefix: <code>{esc(D['apiPrefix'])}</code> · Generated for {esc(D['docRef'])}</footer>
</body></html>"""

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(HTML)
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
