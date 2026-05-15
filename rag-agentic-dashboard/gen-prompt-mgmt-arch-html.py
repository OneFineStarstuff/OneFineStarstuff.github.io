#!/usr/bin/env python3
"""WP-043 — PROMPT-MGMT-ARCH HTML dashboard renderer."""
import json, html
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "prompt-mgmt-arch.json"
OUT = ROOT / "public" / "prompt-mgmt-arch.html"

D = json.loads(SRC.read_text())

def esc(s):
    return html.escape(str(s)) if s is not None else ""

def render_kv(d):
    if not isinstance(d, dict): return esc(d)
    return "<table class='kv'>" + "".join(
        f"<tr><th>{esc(k)}</th><td>{render_value(v)}</td></tr>" for k,v in d.items()
    ) + "</table>"

def render_value(v):
    if isinstance(v, dict): return render_kv(v)
    if isinstance(v, list):
        if v and isinstance(v[0], dict):
            return "<ol>" + "".join(f"<li>{render_kv(x)}</li>" for x in v) + "</ol>"
        return "<ul>" + "".join(f"<li>{esc(i)}</li>" for i in v) + "</ul>"
    return esc(v)

# Modules
mods_html = []
for m in D["modules"]:
    secs = []
    for s in m["sections"]:
        body_html = render_value(s.get("content"))
        secs.append(f"<details class='sec'><summary><b>{esc(s['id'])}</b> — {esc(s['title'])}</summary>{body_html}</details>")
    covers = ""
    if m.get("covers"):
        covers = "<div class='covers'>" + "".join(f"<span class='pill'>{esc(c)}</span>" for c in m["covers"]) + "</div>"
    mods_html.append(f"""
    <article class='module' id='{esc(m['id'])}'>
      <h3>{esc(m['title'])}</h3>
      <p class='summary'>{esc(m.get('summary',''))}</p>
      {covers}
      {''.join(secs)}
    </article>""")

# Personas
persona_rows = "".join(
    f"<tr><td>{esc(p['id'])}</td><td>{esc(p['name'])}</td><td>{esc(p['scope'])}</td></tr>"
    for p in D.get("personas", [])
)

# RBAC
rbac_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['name'])}</td><td>{esc(', '.join(r['scopes']))}</td>"
    f"<td>{esc(r.get('constraints',''))}</td><td>{'yes' if r.get('elevatable') else 'no'}</td></tr>"
    for r in D.get("rbacRoles", [])
)

# KPIs
kpi_rows = "".join(
    f"<tr><td>{esc(k['id'])}</td><td>{esc(k['name'])}</td><td><b>{esc(k['target'])}</b></td></tr>"
    for k in D.get("kpis", [])
)

# Data flows
df_rows = "".join(
    f"<tr><td>{esc(f['id'])}</td><td>{esc(f['name'])}</td><td>{esc(' / '.join(f['steps']))}</td>"
    f"<td>{esc(', '.join(f.get('controls',[])))}</td></tr>"
    for f in D.get("dataFlows", [])
)

# Threats
th_rows = "".join(
    f"<tr><td>{esc(t['id'])}</td><td>{esc(t['category'])}</td><td>{esc(t['vector'])}</td>"
    f"<td>{esc(', '.join(t.get('mitigations',[])))}</td></tr>"
    for t in D.get("threats", [])
)

# Traceability
trace_rows = "".join(
    f"<tr><td>{esc(t['feature'])}</td><td>{esc(t['control'])}</td><td>{esc(', '.join(t['regimes']))}</td></tr>"
    for t in D.get("traceability", [])
)

# Schemas
schema_rows = "".join(
    f"<tr><td>{esc(s['id'])}</td><td>{esc(s['title'])}</td><td>{esc(', '.join(s['fields']))}</td></tr>"
    for s in D["schemas"]
)

# Code
code_html = "".join(
    f"<details class='code'><summary><b>{esc(c['id'])}</b> — {esc(c['title'])} <i>({esc(c['lang'])})</i></summary><pre>{esc(c['snippet'])}</pre></details>"
    for c in D["codeExamples"]
)

# Cases
case_html = "".join(
    f"<article class='case'><h4>{esc(c['id'])} — {esc(c['title'])}</h4><p>{esc(c['summary'])}</p>{render_value(c.get('outcomes',[]))}</article>"
    for c in D["caseStudies"]
)

# Privacy
privacy_html = render_kv(D.get("privacy", {}))

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
  <a href="#personas">Personas</a>
  <a href="#modules">Modules</a>
  <a href="#kpis">KPIs</a>
  <a href="#rbac">RBAC</a>
  <a href="#flows">Data Flows</a>
  <a href="#threats">Threats</a>
  <a href="#privacy">Privacy</a>
  <a href="#trace">Traceability</a>
  <a href="#schemas">Schemas</a>
  <a href="#code">Code</a>
  <a href="#cases">Cases</a>
  <a href="#deploy">Deployment</a>
</nav>
<main>

<section class='block' id='summary'>
  <h2>Executive Summary</h2>
  <p><b>Purpose:</b> {esc(D['executiveSummary']['purpose'])}</p>
  <p><b>Approach:</b> {esc(D['executiveSummary']['approach'])}</p>
  <p><b>Deliverables:</b> {esc(D['executiveSummary']['deliverables'])}</p>
  <h4>Outcomes</h4>
  {render_value(D['executiveSummary']['outcomes'])}
  <h4>Builds On</h4>
  <div>{''.join(f"<span class='pill'>{esc(b)}</span>" for b in D['buildsOn'])}</div>
  <h4>Counts</h4>
  <div class='grid k3'>
    {''.join(f"<div class='stat'><div class='v'>{v}</div><div class='l'>{esc(k)}</div></div>" for k,v in D['counts'].items())}
  </div>
  <h4>Regimes Aligned</h4>
  <div>{''.join(f"<span class='pill'>{esc(r)}</span>" for r in D['regimes'])}</div>
</section>

<section class='block' id='personas'>
  <h2>Personas ({len(D['personas'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Scope</th></tr></thead><tbody>{persona_rows}</tbody></table>
</section>

<section class='block' id='modules'>
  <h2>Modules ({len(D['modules'])})</h2>
  {''.join(mods_html)}
</section>

<section class='block' id='kpis'>
  <h2>Supervisory KPIs ({len(D['kpis'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Target</th></tr></thead><tbody>{kpi_rows}</tbody></table>
</section>

<section class='block' id='rbac'>
  <h2>RBAC Role Catalogue ({len(D['rbacRoles'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Scopes</th><th>Constraints</th><th>JIT-elevatable</th></tr></thead><tbody>{rbac_rows}</tbody></table>
</section>

<section class='block' id='flows'>
  <h2>Data Flows ({len(D['dataFlows'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Steps</th><th>Controls</th></tr></thead><tbody>{df_rows}</tbody></table>
</section>

<section class='block' id='threats'>
  <h2>Threats (STRIDE + OWASP LLM Top 10) ({len(D['threats'])})</h2>
  <table><thead><tr><th>ID</th><th>Category</th><th>Vector</th><th>Mitigations</th></tr></thead><tbody>{th_rows}</tbody></table>
</section>

<section class='block' id='privacy'>
  <h2>Privacy (GDPR-Aligned)</h2>
  {privacy_html}
</section>

<section class='block' id='trace'>
  <h2>Traceability — Feature → Control → Regime</h2>
  <table><thead><tr><th>Feature</th><th>Control</th><th>Regimes</th></tr></thead><tbody>{trace_rows}</tbody></table>
</section>

<section class='block' id='schemas'>
  <h2>Schemas ({len(D['schemas'])})</h2>
  <table><thead><tr><th>ID</th><th>Title</th><th>Fields</th></tr></thead><tbody>{schema_rows}</tbody></table>
</section>

<section class='block' id='code'>
  <h2>Code Examples ({len(D['codeExamples'])})</h2>
  {code_html}
</section>

<section class='block' id='cases'>
  <h2>Case Studies ({len(D['caseStudies'])})</h2>
  <div class='grid k2'>{case_html}</div>
</section>

<section class='block' id='deploy'>
  <h2>Deployment Considerations</h2>
  {render_value(D['deploymentConsiderations'])}
</section>

</main>
<footer>API prefix: <code>{esc(D['apiPrefix'])}</code> · Generated for {esc(D['docRef'])}</footer>
</body></html>"""

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(HTML)
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
