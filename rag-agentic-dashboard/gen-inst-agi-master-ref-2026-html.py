#!/usr/bin/env python3
"""WP-052 — INST-AGI-MASTER-REF-2026 HTML dashboard renderer."""
import json, html
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "inst-agi-master-ref-2026.json"
OUT = ROOT / "public" / "inst-agi-master-ref-2026.html"

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

kpi_rows = "".join(
    f"<tr><td>{esc(k['id'])}</td><td>{esc(k['name'])}</td><td><b>{esc(k['target'])}</b></td><td>{esc(k.get('frequency',''))}</td><td>{esc(k.get('owner',''))}</td></tr>"
    for k in D["kpis"]
)
reg_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['name'])}</td><td>{esc(r.get('regime',''))}</td><td>{esc(', '.join(r.get('submissions',[])))}</td></tr>"
    for r in D["regulators"]
)
ws_rows = "".join(
    f"<tr><td>{esc(w['id'])}</td><td>{esc(w['name'])}</td><td>{esc(w['audience'])}</td><td>{esc(w['duration'])}</td><td>{esc(w.get('cadence',''))}</td></tr>"
    for w in D["workshops"]
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
case_html = "".join(
    f"<article class='case'><h4>{esc(c['id'])} — {esc(c['name'])}</h4><p><b>Scope:</b> {esc(c.get('scope',''))}</p><p><b>Regime:</b> {esc(', '.join(c.get('regime',[])))}</p><p><b>Outcomes:</b> {esc(c['outcomes'])}</p></article>"
    for c in D["cases"]
)
rollout_rows = "".join(
    f"<tr><td>{esc(r['phase'])}</td><td>{render_value(r.get('deliverables',[]))}</td><td>{esc(r.get('exitGate',''))}</td></tr>"
    for r in D["rollout90"]
)
roadmap_rows = "".join(
    f"<tr><td>{esc(r['year'])}</td><td>{render_value(r.get('themes',[]))}</td><td>{esc(', '.join(r.get('gates',[])))}</td></tr>"
    for r in D["roadmap"]
)
report_html = "".join(
    f"<details class='code'><summary><b>{esc(r['id'])}</b> — {esc(r['title'])}</summary>"
    f"<p class='summary'><b>Abstract:</b> {esc(r['abstract'])}</p>"
    f"<p>{esc(r['content'])}</p>"
    f"<h5>Pre-rendered tagged payload</h5><pre>{esc(r['tagged'])}</pre>"
    f"</details>"
    for r in D["reportSections"]
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
  article.case {{ background:#0e1730; border:1px solid #1c2742; border-radius:12px; padding:12px }}
  article.case h4 {{ margin:0 0 6px; color:var(--accent) }}
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
  <a href="#kpis">KPIs</a>
  <a href="#rcm">Risk &amp; Control</a>
  <a href="#regulators">Regulators</a>
  <a href="#workshops">Workshops</a>
  <a href="#dataflows">Data Flows</a>
  <a href="#trace">Traceability</a>
  <a href="#schemas">Schemas</a>
  <a href="#code">Code</a>
  <a href="#cases">Cases</a>
  <a href="#reports">Report Sections</a>
  <a href="#rollout">30/60/90</a>
  <a href="#roadmap">2026-2030</a>
  <a href="#evidence">Evidence Pack</a>
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
  <h2>Modules ({len(D['modules'])})</h2>
  {''.join(mods_html)}
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

<section class='block' id='workshops'>
  <h2>Workshops ({len(D['workshops'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Audience</th><th>Duration</th><th>Cadence</th></tr></thead><tbody>{ws_rows}</tbody></table>
</section>

<section class='block' id='dataflows'>
  <h2>Data Flows ({len(D['dataFlows'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>From → To</th><th>Controls</th><th>WORM Topic</th></tr></thead><tbody>{df_rows}</tbody></table>
</section>

<section class='block' id='trace'>
  <h2>Traceability — Requirement → Control → Evidence ({len(D['traceability'])})</h2>
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

<section class='block' id='cases'>
  <h2>Case Studies ({len(D['cases'])})</h2>
  <div class='grid k2'>{case_html}</div>
</section>

<section class='block' id='reports'>
  <h2>Regulator-Ready Report Sections ({len(D['reportSections'])}) — R-01..R-12</h2>
  <p class='summary'>Each section carries <code>&lt;title&gt;</code>, <code>&lt;abstract&gt;</code>, and <code>&lt;content&gt;</code> tags ready for AISRG submission.</p>
  {report_html}
</section>

<section class='block' id='rollout'>
  <h2>30/60/90-Day Rollout</h2>
  <table><thead><tr><th>Phase</th><th>Deliverables</th><th>Exit Gate</th></tr></thead><tbody>{rollout_rows}</tbody></table>
</section>

<section class='block' id='roadmap'>
  <h2>2026-2030 Multi-Year Roadmap ({len(D['roadmap'])} years)</h2>
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
