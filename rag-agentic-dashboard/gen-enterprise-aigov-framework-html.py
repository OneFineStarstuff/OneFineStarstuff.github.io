#!/usr/bin/env python3
"""WP-058 HTML renderer — Enterprise AI/AGI Governance Framework 2026-2030."""
import json
from pathlib import Path
from html import escape

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "enterprise-aigov-framework.json"
OUT = ROOT / "public" / "enterprise-aigov-framework.html"
OUT.parent.mkdir(parents=True, exist_ok=True)
DOC = json.loads(SRC.read_text())


def e(x):
    return escape(str(x))


SKIP = (
    "mid", "sid", "title", "pid", "cid", "wid", "tid", "kid", "oid", "rid", "aid", "hid",
    "name", "layer", "component", "system", "area", "category", "mechanism", "riskClass",
    "control", "phase", "milestone", "regime", "clause", "blueprint", "framework", "theme",
    "track", "scope", "domain", "statement", "family", "vector", "technique", "tier",
    "regoRef", "lifecycle", "artifact",
)


def kv_pairs(d, skip=SKIP):
    parts = []
    for k, v in d.items():
        if k in skip:
            continue
        if isinstance(v, list):
            inner = "".join(
                f"<li>{e(x) if not isinstance(x, dict) else e(json.dumps(x))}</li>"
                for x in v
            )
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
    return f"<section id='{anchor}'><h3>{title} ({len(arr)})</h3>{''.join(rows)}</section>"


distinctive = [
    ("policies",       "policies",        "Enterprise AI Policies", ["pid", "domain", "statement"]),
    ("controls",       "controls",        "Control Catalog",         ["cid", "family", "control"]),
    ("kafkaTopics",    "kafka-topics",    "Kafka Audit Topics",      ["tid", "name", "schema"]),
    ("k8sControls",    "k8s-controls",    "Kubernetes/Container Security Controls", ["kid", "area", "mechanism"]),
    ("opaPolicies",    "opa-policies",    "OPA/Rego Policies",       ["oid", "area", "regoRef"]),
    ("wormControls",   "worm-controls",   "WORM + PQC Controls",     ["wid", "layer", "mechanism"]),
    ("mrmArtifacts",   "mrm-artifacts",   "Model Risk Management Artifacts", ["mid", "lifecycle", "artifact"]),
    ("redTeams",       "red-teams",       "Red-Teaming Attack Surface", ["rid", "vector", "technique"]),
    ("agiContainments","agi-containments","AGI/ASI Containment Mechanisms", ["aid", "tier", "mechanism"]),
    ("hubComponents",  "hub-components",  "AI Governance Hub Components", ["hid", "layer", "component"]),
]

toc_modules = "".join(
    f"<li><a href='#{e(m['mid'])}'>{e(m['mid'])} — {e(m['title'])}</a></li>"
    for m in DOC["modules"]
)
toc_distinct = "".join(
    f"<li><a href='#{anchor}'>{e(label)}</a></li>"
    for _, anchor, label, _ in distinctive
)

modules_html = "".join(module_html(m) for m in DOC["modules"])
distinctive_html = "".join(
    list_array(DOC[key], keys, anchor, label)
    for key, anchor, label, keys in distinctive
)


def table(rows, cols):
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body_rows = []
    for r in rows:
        tds = "".join(f"<td>{e(r.get(c, ''))}</td>" for c in cols)
        body_rows.append(f"<tr>{tds}</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


tail_html = f"""
<section id='schemas'><h3>Schemas ({len(DOC['schemas'])})</h3>{table(DOC['schemas'], ['sid','name','fields'])}</section>
<section id='code'><h3>Code Artifacts ({len(DOC['code'])})</h3>{table(DOC['code'], ['cid','lang','name','purpose'])}</section>
<section id='kpis'><h3>KPIs ({len(DOC['kpis'])})</h3>{table(DOC['kpis'], ['kid','name','target','cadence'])}</section>
<section id='rcm'><h3>Risk Control Matrix ({len(DOC['riskControlMatrix'])})</h3>{table(DOC['riskControlMatrix'], ['rid','risk','likelihood','impact','control','owner'])}</section>
<section id='trace'><h3>Cross-Jurisdictional Traceability ({len(DOC['traceability'])})</h3>{table(DOC['traceability'], ['tid','control','regime','clause','evidence'])}</section>
<section id='data-flows'><h3>Data Flows ({len(DOC['dataFlows'])})</h3>{table(DOC['dataFlows'], ['fid','src','sink','class','purpose'])}</section>
<section id='regulators'><h3>Regulators ({len(DOC['regulators'])})</h3>{table(DOC['regulators'], ['reg','scope','cadence'])}</section>
<section id='rollout-90'><h3>90-Day Rollout ({len(DOC['rollout90'])})</h3>{table(DOC['rollout90'], ['day','focus','deliverables'])}</section>
<section id='roadmap'><h3>2026-2030 Roadmap ({len(DOC['roadmap'])})</h3>{table(DOC['roadmap'], ['yr','milestone'])}</section>
<section id='evidence-pack'><h3>Regulator Evidence Pack ({len(DOC['evidencePack'])})</h3>{table(DOC['evidencePack'], ['epid','name','format'])}</section>
"""

exs = DOC["executiveSummary"]
exec_html = f"""
<section id='exec'><h3>Executive Summary</h3>
<p><b>Thesis:</b> {e(exs['thesis'])}</p>
<p><b>Investment:</b> {e(exs['investment'])}</p>
<p><b>Headline risks:</b> {', '.join(e(x) for x in exs['headlineRisks'])}</p>
<p><b>First 90 days:</b> {', '.join(e(x) for x in exs['ninetyDay'])}</p>
</section>
"""

# Directive + indices + tiers + severities + investment
directive = DOC["directive"]
indices_rows = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in DOC["indices"].items())
tiers_rows = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in DOC["tiers"].items())
sev_rows = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in DOC["severities"].items())
invest = DOC["investment"]
invest_drivers = "".join(f"<li>{e(x)}</li>" for x in invest["drivers"])
regimes_list = "".join(f"<li>{e(r)}</li>" for r in DOC["regimes"])

meta_html = f"""
<section id='directive'><h3>Strategic Directive</h3>
<p><b>Scope:</b> {e(directive['scope'])}</p>
<div class='kv'><b>Outcomes</b><ul>{''.join(f'<li>{e(x)}</li>' for x in directive['outcomes'])}</ul></div>
<div class='kv'><b>Do NOT</b><ul>{''.join(f'<li>{e(x)}</li>' for x in directive['doNot'])}</ul></div>
</section>

<section id='regimes'><h3>Regulatory Regimes ({len(DOC['regimes'])})</h3><ul>{regimes_list}</ul></section>

<section id='indices'><h3>Performance Indices</h3><ul>{indices_rows}</ul></section>

<section id='tiers'><h3>Tiers (T0-T4)</h3><ul>{tiers_rows}</ul></section>

<section id='severities'><h3>Severity Levels</h3><ul>{sev_rows}</ul></section>

<section id='investment'><h3>Investment Envelope</h3>
<p><b>Envelope:</b> {e(invest['envelope'])} · <b>NPV:</b> {e(invest['NPV'])}</p>
<div class='kv'><b>Drivers</b><ul>{invest_drivers}</ul></div>
</section>

<section id='privacy'><h3>Privacy & Data Protection</h3>
{kv_pairs(DOC['privacy'])}
</section>

<section id='deployment'><h3>Deployment Model</h3>
{kv_pairs(DOC['deployment'])}
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
code {{ background:#0e141b; padding:1px 4px; border-radius:3px; font-size:12px; }}
@media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; }} nav.toc {{ position:relative; height:auto; }} main {{ padding:20px; }} }}
</style>
</head><body>
<header>
<h1>{e(DOC['title'])}</h1>
<div class="meta">docRef <b>{e(DOC['docRef'])}</b> · v{e(DOC['version'])} · {e(DOC['status'])} · {e(DOC['classification'])}</div>
<div class="meta">Horizon: {e(DOC['horizon'])} · API prefix: <code>{e(DOC['apiPrefix'])}</code> · builds on {' · '.join(e(b) for b in DOC['buildsOn'])}</div>
<div class="counts">
{''.join(f"<span><b>{v}</b> {e(k)}</span>" for k,v in DOC['counts'].items())}
</div>
</header>
<div class="layout">
<nav class="toc">
<h4>Executive</h4>
<ul>
<li><a href='#exec'>Executive Summary</a></li>
<li><a href='#directive'>Strategic Directive</a></li>
<li><a href='#regimes'>Regulatory Regimes</a></li>
<li><a href='#indices'>Indices</a></li>
<li><a href='#tiers'>Tiers</a></li>
<li><a href='#severities'>Severities</a></li>
<li><a href='#investment'>Investment</a></li>
</ul>
<h4>Modules (M1-M9)</h4>
<ul>{toc_modules}</ul>
<h4>Distinctive Arrays</h4>
<ul>{toc_distinct}</ul>
<h4>Tail Tables</h4>
<ul>
<li><a href='#schemas'>Schemas</a></li>
<li><a href='#code'>Code Artifacts</a></li>
<li><a href='#kpis'>KPIs</a></li>
<li><a href='#rcm'>Risk Control Matrix</a></li>
<li><a href='#trace'>Traceability</a></li>
<li><a href='#data-flows'>Data Flows</a></li>
<li><a href='#regulators'>Regulators</a></li>
<li><a href='#privacy'>Privacy</a></li>
<li><a href='#deployment'>Deployment</a></li>
<li><a href='#rollout-90'>90-Day Rollout</a></li>
<li><a href='#roadmap'>2026-2030 Roadmap</a></li>
<li><a href='#evidence-pack'>Evidence Pack</a></li>
</ul>
</nav>
<main>
{exec_html}
{meta_html}
{modules_html}
{distinctive_html}
{tail_html}
</main>
</div>
</body></html>
"""

OUT.write_text(html, encoding="utf-8")
print(f"WP-058 HTML written: {OUT}")
print(f"Size: {OUT.stat().st_size:,} bytes ({OUT.stat().st_size/1024:.1f} KB)")
