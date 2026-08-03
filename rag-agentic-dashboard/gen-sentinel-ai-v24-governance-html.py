#!/usr/bin/env python3
"""WP-055 — Sentinel AI v2.4 Enterprise AGI/ASI Governance & Containment HTML renderer."""
import json, html
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "sentinel-ai-v24-governance.json"
OUT = ROOT / "public" / "sentinel-ai-v24-governance.html"

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


# ============================================================
# Modules
# ============================================================
mods_html = []
for m in D["modules"]:
    secs = []
    for s in m["sections"]:
        body_html = render_value(s.get("content"))
        refs = f"<p class='muted'><b>Refs:</b> {esc(', '.join(s.get('refs',[])))}</p>" if s.get("refs") else ""
        ctrl = f"<p class='muted'><b>Controls:</b> {esc(', '.join(s.get('controls',[])))}</p>" if s.get("controls") else ""
        ev = f"<p class='muted'><b>Evidence:</b> {esc(', '.join(s.get('evidence',[])))}</p>" if s.get("evidence") else ""
        rg = f"<p class='muted'><b>Regimes:</b> {esc(', '.join(s.get('regimes',[])))}</p>" if s.get("regimes") else ""
        secs.append(
            f"<details class='sec'><summary><b>{esc(s['sid'])}</b> — {esc(s['title'])}</summary>{body_html}{refs}{ctrl}{ev}{rg}</details>"
        )
    mods_html.append(f"""
    <article class='module' id='{esc(m['mid'])}'>
      <h3>{esc(m['mid'])} · {esc(m['title'])} <span class='pill'>{esc(m.get('scopeItem',''))}</span></h3>
      {''.join(secs)}
    </article>""")

# ============================================================
# Common tables
# ============================================================
kpi_rows = "".join(
    f"<tr><td>{esc(k['id'])}</td><td>{esc(k['name'])}</td><td><b>{esc(k['target'])}</b></td><td>{esc(k.get('frequency',''))}</td><td>{esc(k.get('owner',''))}</td><td>{esc(k.get('regime',''))}</td></tr>"
    for k in D["kpis"]
)
reg_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['name'])}</td><td>{esc(r.get('jurisdiction',''))}</td><td>{esc(', '.join(r.get('applicableRegs',[])))}</td><td>{esc(r.get('engagementClock',''))}</td></tr>"
    for r in D["regulators"]
)
df_rows = "".join(
    f"<tr><td>{esc(d['id'])}</td><td>{esc(d['name'])}</td><td>{esc(d.get('source',''))} → {esc(d.get('sink',''))}</td><td>{esc(d.get('transport',''))}</td><td>{esc(d.get('protection',''))}</td><td>{esc(d.get('classification',''))}</td></tr>"
    for d in D["dataFlows"]
)
trace_rows = "".join(
    f"<tr><td>{esc(t['id'])}</td><td>{esc(t['module'])}</td><td>{esc(t.get('section',''))}</td><td>{esc(t.get('control',''))}</td><td>{esc(t.get('regime',''))}</td><td>{esc(t.get('evidence',''))}</td></tr>"
    for t in D["traceability"]
)
rc_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r['risk'])}</td><td>{esc(r.get('likelihood',''))}</td><td>{esc(r.get('impact',''))}</td><td>{esc(r.get('control',''))}</td><td>{esc(r.get('owner',''))}</td><td>{esc(r.get('regime',''))}</td></tr>"
    for r in D["riskControlMatrix"]
)
schema_rows = "".join(
    f"<tr><td>{esc(s['id'])}</td><td>{esc(s['name'])}</td><td>{esc(s.get('format',''))}</td><td>{esc(', '.join(s['fields']))}</td><td>{esc(', '.join(s.get('regimes',[])))}</td></tr>"
    for s in D["schemas"]
)
code_html = "".join(
    f"<details class='code' id='{esc(c['id'])}'><summary><b>{esc(c['id'])}</b> — {esc(c['name'])} <i>({esc(c['language'])})</i></summary>"
    f"<p class='muted'>{esc(c.get('purpose',''))}</p>"
    f"<pre>{esc(c['snippet'])}</pre></details>"
    for c in D["code"]
)
rollout_rows = "".join(
    f"<tr><td>{esc(r['id'])}</td><td>{esc(r.get('window',''))}</td><td>{esc(r.get('focus',''))}</td><td>{render_value(r.get('activities',[]))}</td></tr>"
    for r in D["rollout90"]
)
roadmap_rows = "".join(
    f"<tr><td>{esc(r['year'])}</td><td>{esc(r.get('theme',''))}</td><td>{render_value(r.get('milestones',[]))}</td></tr>"
    for r in D["roadmap"]
)
evidence_rows = "".join(
    f"<tr><td>{esc(e['id'])}</td><td>{esc(e['artifact'])}</td><td><code>{esc(e['location'])}</code></td></tr>"
    for e in D["evidencePack"]
)

# ============================================================
# 9 distinctive arrays
# ============================================================
# S1 — Governance Roles
gr_rows = "".join(
    f"<tr><td>{esc(g['rid'])}</td><td><b>{esc(g['role'])}</b></td><td>{esc(g.get('scope',''))}</td>"
    f"<td>{render_value(g.get('responsibilities',[]))}</td>"
    f"<td>{render_value(g.get('decisionRights',[]))}</td>"
    f"<td>{esc(', '.join(g.get('regimes',[])))}</td></tr>"
    for g in D["governanceRoles"]
)

# S2 — React Components
rc_html = "".join(
    f"<details class='code' id='{esc(c['cid'])}'><summary><b>{esc(c['cid'])}</b> — {esc(c['component'])}</summary>"
    f"<p class='muted'><b>Purpose:</b> {esc(c.get('purpose',''))}</p>"
    f"<p><b>State Model:</b> <code>{esc(c.get('stateModel',''))}</code></p>"
    f"<p><b>Props:</b> <code>{esc(c.get('props',''))}</code></p>"
    f"<p><b>Security Controls:</b> {esc(', '.join(c.get('securityControls',[])))}</p>"
    f"<p><b>Accessibility:</b> {esc(c.get('accessibility',''))}</p>"
    f"</details>"
    for c in D["reactComponents"]
)

# S3 — Containment Proxy Layers
cp_rows = "".join(
    f"<tr><td>{esc(p['pid'])}</td><td><b>{esc(p['layer'])}</b></td><td>{esc(p.get('function',''))}</td>"
    f"<td>{esc(p.get('securityModel',''))}</td>"
    f"<td>{esc(p.get('controls',''))}</td>"
    f"<td>{esc(p.get('telemetry',''))}</td>"
    f"<td>{'Yes' if p.get('failClosed') else 'No'}</td></tr>"
    for p in D["containmentProxy"]
)

# S4 — Terraform IaC modules
tf_html = "".join(
    f"<details class='code' id='{esc(t['tid'])}'><summary><b>{esc(t['tid'])}</b> — {esc(t['module'])}</summary>"
    f"<p><b>Resources:</b> {esc(', '.join(t.get('resources',[])))}</p>"
    f"<p><b>Hardening:</b> {esc(', '.join(t.get('hardening',[])))}</p>"
    f"<p><b>Compliance Mappings:</b> {esc(', '.join(t.get('complianceMappings',[])))}</p>"
    f"<p><b>Misconfigs Fixed:</b> {esc(', '.join(t.get('misconfigsFixed',[])))}</p>"
    f"</details>"
    for t in D["terraformIaC"]
)

# S5 — MLSecOps Pipeline stages
ci_rows = "".join(
    f"<tr><td>{esc(s['sid'])}</td><td><b>{esc(s['stage'])}</b></td>"
    f"<td>{esc(', '.join(s.get('jobs',[])))}</td>"
    f"<td>{esc(', '.join(s.get('gates',[])))}</td>"
    f"<td>{esc(s.get('evidence',''))}</td>"
    f"<td>{esc(s.get('slaMin',''))} min</td></tr>"
    for s in D["mlsecopsPipeline"]
)

# S6 — Incident Response steps
ir_rows = "".join(
    f"<tr><td>{esc(i['iid'])}</td><td><b>{esc(i['step'])}</b></td>"
    f"<td>{esc(i.get('owner',''))}</td>"
    f"<td>{esc(i.get('sla',''))}</td>"
    f"<td>{esc(i.get('automation',''))}</td>"
    f"<td>{esc(i.get('escalation',''))}</td>"
    f"<td>{esc(i.get('evidence',''))}</td></tr>"
    for i in D["incidentResponse"]
)

# S7 — Compliance Analysis (AGI-TRADER-PROD-01)
ca_html = "".join(
    f"<details class='code' id='{esc(c['cid'])}'><summary><b>{esc(c['cid'])}</b> — {esc(c['clause'])} <i>({esc(c.get('citation',''))})</i></summary>"
    f"<p class='muted'><b>Requirement:</b> {esc(c.get('requirement',''))}</p>"
    f"<p><b>Sentinel Control:</b> {esc(c.get('sentinelControl',''))}</p>"
    f"<p><b>Evidence:</b> {esc(c.get('evidence',''))}</p>"
    f"<p><b>Residual Risk:</b> <span class='pill'>{esc(c.get('residualRisk',''))}</span></p>"
    f"</details>"
    for c in D["complianceAnalysis"]
)

# S8 — Kafka Sandbox / Adversarial Tests
at_rows = "".join(
    f"<tr><td>{esc(a['aid'])}</td><td>{esc(a['category'])}</td>"
    f"<td>{esc(a.get('attackVector',''))}</td>"
    f"<td>{esc(a.get('technique',''))}</td>"
    f"<td>{esc(a.get('expectedDetection',''))}</td>"
    f"<td>{esc(a.get('mitreAtlas',''))}</td>"
    f"<td><span class='pill'>{esc(a.get('severity',''))}</span></td></tr>"
    for a in D["kafkaSandbox"]
)

# S9 — Sentinel Architecture nodes
arch_rows = "".join(
    f"<tr><td>{esc(n['nid'])}</td><td><b>{esc(n['layer'])}</b></td>"
    f"<td>{esc(n.get('component',''))}</td>"
    f"<td>{esc(', '.join(n.get('dependencies',[])))}</td>"
    f"<td>{esc(', '.join(n.get('dataFlows',[])))}</td>"
    f"<td>{esc(n.get('securityPosture',''))}</td>"
    f"<td>{esc(n.get('slaUptime',''))}</td></tr>"
    for n in D["sentinelArchitecture"]
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
  .muted {{ color:var(--muted); margin:6px 0 }}
  details {{ background:#0e1730; border:1px solid #1c2742; border-radius:10px; padding:8px 12px; margin:6px 0 }}
  details summary {{ cursor:pointer; color:var(--ink) }}
  .grid {{ display:grid; gap:14px }}
  .grid.k3 {{ grid-template-columns:repeat(3,1fr) }}
  .stat {{ background:#0e1730; border:1px solid #1c2742; border-radius:12px; padding:14px }}
  .stat .v {{ font-size:24px; font-weight:700; color:var(--accent) }}
  .stat .l {{ color:var(--muted); font-size:12px }}
  article.module {{ background:#0e1730; border:1px solid #1c2742; border-radius:12px; padding:14px; margin:10px 0 }}
  article.module h3 {{ margin:0 0 8px; color:var(--ink) }}
  footer {{ padding:24px 32px; color:var(--muted); font-size:11px; border-top:1px solid #1c2742 }}
  code {{ background:#0a1226; padding:1px 6px; border-radius:6px; font-size:12px }}
</style>
</head><body>
<header>
  <h1>{esc(D['title'])}</h1>
  <div class='meta'><b>{esc(D['docRef'])}</b> · v{esc(D['version'])} · {esc(D['horizon'])}</div>
  <div class='meta'>API prefix: <code>{esc(D['apiPrefix'])}</code></div>
</header>
<nav>
  <a href="#summary">Summary</a>
  <a href="#directive">Directive</a>
  <a href="#modules">Modules</a>
  <a href="#roles">S1 Roles</a>
  <a href="#react">S2 React</a>
  <a href="#proxy">S3 Proxy</a>
  <a href="#terraform">S4 Terraform</a>
  <a href="#mlsecops">S5 MLSecOps</a>
  <a href="#ir">S6 Incidents</a>
  <a href="#compliance">S7 Compliance</a>
  <a href="#adversary">S8 Adversary</a>
  <a href="#arch">S9 Architecture</a>
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
  <p><b>Investment:</b> {esc(D['executiveSummary'].get('investment',''))}</p>
  <p><b>NPV:</b> {esc(D['executiveSummary'].get('npv',''))}</p>
  <h4>Audience</h4>
  <div>{''.join(f"<span class='pill'>{esc(a)}</span>" for a in D['executiveSummary'].get('audience',[]))}</div>
  <h4>Key Asks</h4>
  {render_value(D['executiveSummary'].get('keyAsks',[]))}
  <h4>Builds On</h4>
  <div>{''.join(f"<span class='pill'>{esc(b)}</span>" for b in D.get('buildsOn',[]))}</div>
  <h4>Counts</h4>
  <div class='grid k3'>
    {''.join(f"<div class='stat'><div class='v'>{v}</div><div class='l'>{esc(k)}</div></div>" for k,v in D['counts'].items())}
  </div>
  <h4>Regimes Aligned ({len(D.get('regimes',[]))})</h4>
  <div>{''.join(f"<span class='pill'>{esc(r)}</span>" for r in D.get('regimes',[]))}</div>
</section>

<section class='block' id='directive'>
  <h2>Directive — Sentinel AI v2.4 Containment</h2>
  {render_kv(D.get('directive',{}))}
</section>

<section class='block' id='modules'>
  <h2>Modules ({len(D['modules'])}) — One per Scope Item S1–S9 · {sum(len(m['sections']) for m in D['modules'])} sections</h2>
  {''.join(mods_html)}
</section>

<section class='block' id='roles'>
  <h2>S1 — Governance Roles ({len(D['governanceRoles'])})</h2>
  <p class='muted'>Board, CAIO, CRO, CISO, CDO, CCO, CTO, Head of MRM, Internal Audit, Red Team, Privacy — responsibilities, decision rights, regimes.</p>
  <table><thead><tr><th>ID</th><th>Role</th><th>Scope</th><th>Responsibilities</th><th>Decision Rights</th><th>Regimes</th></tr></thead><tbody>{gr_rows}</tbody></table>
</section>

<section class='block' id='react'>
  <h2>S2 — React AGI Governance Hub Components ({len(D['reactComponents'])})</h2>
  <p class='muted'>Hub root, Agent Registry, Incident Tracker, Isolation Panel, Live Risk Score, Swarm Topology, SCADA Kinetic, Interrogation Terminal, WORM Ledger UI, Evidence Export.</p>
  {rc_html}
</section>

<section class='block' id='proxy'>
  <h2>S3 — Flask Containment Proxy Layers ({len(D['containmentProxy'])})</h2>
  <p class='muted'>Zero-trust edge, DLP inbound/outbound, constitutional guard, OPA policy, Nitro tripwire, vsock bridge, PQC signer, WORM committer, telemetry — all fail-closed.</p>
  <table><thead><tr><th>ID</th><th>Layer</th><th>Function</th><th>Security Model</th><th>Controls</th><th>Telemetry</th><th>Fail-Closed</th></tr></thead><tbody>{cp_rows}</tbody></table>
</section>

<section class='block' id='terraform'>
  <h2>S4 — Terraform IaC Modules ({len(D['terraformIaC'])})</h2>
  <p class='muted'>sentinel-eks, sentinel-nitro, sentinel-worm, sentinel-iam, sentinel-network-firewall, sentinel-cloudhsm, sentinel-kafka, sentinel-monitoring.</p>
  {tf_html}
</section>

<section class='block' id='mlsecops'>
  <h2>S5 — MLSecOps GitHub Actions Pipeline ({len(D['mlsecopsPipeline'])} stages)</h2>
  <p class='muted'>12-stage pipeline: pre-commit → secret scan → Terraform → container → unit → adversary → mech-interp → policy → provenance → T1 → T2 canary → prod gate.</p>
  <table><thead><tr><th>ID</th><th>Stage</th><th>Jobs</th><th>Gates</th><th>Evidence</th><th>SLA</th></tr></thead><tbody>{ci_rows}</tbody></table>
</section>

<section class='block' id='ir'>
  <h2>S6 — SEV-0 Incident Response Playbook ({len(D['incidentResponse'])} steps)</h2>
  <p class='muted'>Auto kinetic hold → PD SEV-0 → WORM snapshot → regulator clock → war-room → containment → filing → RCA → CA → lessons learned → Board → IA review.</p>
  <table><thead><tr><th>ID</th><th>Step</th><th>Owner</th><th>SLA</th><th>Automation</th><th>Escalation</th><th>Evidence</th></tr></thead><tbody>{ir_rows}</tbody></table>
</section>

<section class='block' id='compliance'>
  <h2>S7 — AGI-TRADER-PROD-01 Compliance Analysis ({len(D['complianceAnalysis'])} clauses)</h2>
  <p class='muted'>EU AI Act Arts. 53/55, SR 11-7 §V/§VI, ISO 42001 §6, SEC 17a-4(f), FCRA 615(a) — clause-by-clause mapping with Sentinel controls, evidence, and residual risk.</p>
  {ca_html}
</section>

<section class='block' id='adversary'>
  <h2>S8 — Adversarial LLM Security Test Suite ({len(D['kafkaSandbox'])} tests)</h2>
  <p class='muted'>5 categories × 2 representative tests: jailbreaks, systemic financial risk, privacy violations, containment escape, deceptive alignment — with MITRE ATLAS technique mapping.</p>
  <table><thead><tr><th>ID</th><th>Category</th><th>Attack Vector</th><th>Technique</th><th>Expected Detection</th><th>MITRE ATLAS</th><th>Severity</th></tr></thead><tbody>{at_rows}</tbody></table>
</section>

<section class='block' id='arch'>
  <h2>S9 — End-to-End Sentinel Architecture ({len(D['sentinelArchitecture'])} nodes)</h2>
  <p class='muted'>10-node architecture: Edge · Containment · Guard · Policy · Compute (Nitro) · Telemetry (Kafka) · Persistence (S3 WORM) · UI · Ops · Kinetic — with dependencies, data flows, security posture, SLA.</p>
  <table><thead><tr><th>ID</th><th>Layer</th><th>Component</th><th>Dependencies</th><th>Data Flows</th><th>Security Posture</th><th>SLA Uptime</th></tr></thead><tbody>{arch_rows}</tbody></table>
</section>

<section class='block' id='kpis'>
  <h2>Supervisory KPIs ({len(D['kpis'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Target</th><th>Frequency</th><th>Owner</th><th>Regime</th></tr></thead><tbody>{kpi_rows}</tbody></table>
</section>

<section class='block' id='rcm'>
  <h2>Risk &amp; Control Matrix ({len(D['riskControlMatrix'])})</h2>
  <table><thead><tr><th>ID</th><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Control</th><th>Owner</th><th>Regime</th></tr></thead><tbody>{rc_rows}</tbody></table>
</section>

<section class='block' id='regulators'>
  <h2>Regulators ({len(D['regulators'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Jurisdiction</th><th>Applicable Regs</th><th>Engagement Clock</th></tr></thead><tbody>{reg_rows}</tbody></table>
</section>

<section class='block' id='dataflows'>
  <h2>Data Flows ({len(D['dataFlows'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Source → Sink</th><th>Transport</th><th>Protection</th><th>Classification</th></tr></thead><tbody>{df_rows}</tbody></table>
</section>

<section class='block' id='trace'>
  <h2>Traceability ({len(D['traceability'])})</h2>
  <table><thead><tr><th>ID</th><th>Module</th><th>Section</th><th>Control</th><th>Regime</th><th>Evidence</th></tr></thead><tbody>{trace_rows}</tbody></table>
</section>

<section class='block' id='schemas'>
  <h2>Schemas ({len(D['schemas'])})</h2>
  <table><thead><tr><th>ID</th><th>Name</th><th>Format</th><th>Fields</th><th>Regimes</th></tr></thead><tbody>{schema_rows}</tbody></table>
</section>

<section class='block' id='code'>
  <h2>Code Examples ({len(D['code'])})</h2>
  {code_html}
</section>

<section class='block' id='roadmap'>
  <h2>90-Day Rollout + 2026-2030 Roadmap</h2>
  <h3>90-Day Rollout</h3>
  <table><thead><tr><th>ID</th><th>Window</th><th>Focus</th><th>Activities</th></tr></thead><tbody>{rollout_rows}</tbody></table>
  <h3>2026-2030 Roadmap ({len(D['roadmap'])} years)</h3>
  <table><thead><tr><th>Year</th><th>Theme</th><th>Milestones</th></tr></thead><tbody>{roadmap_rows}</tbody></table>
</section>

<section class='block' id='evidence'>
  <h2>Evidence Pack ({len(D['evidencePack'])})</h2>
  <table><thead><tr><th>ID</th><th>Artifact</th><th>Location</th></tr></thead><tbody>{evidence_rows}</tbody></table>
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
<footer>API prefix: <code>{esc(D['apiPrefix'])}</code> · Generated for {esc(D['docRef'])} v{esc(D['version'])}</footer>
</body></html>"""

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(HTML)
print(f"Generated {OUT} ({OUT.stat().st_size/1024:.1f} KB)")
