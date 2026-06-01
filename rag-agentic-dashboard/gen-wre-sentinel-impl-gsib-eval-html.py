#!/usr/bin/env python3
"""WP-063 HTML renderer — WRE + Sentinel implementation spec & G-SIB 5-year evaluation."""
import json
from pathlib import Path
from html import escape

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "data" / "wre-sentinel-impl-gsib-eval.json"
OUT = ROOT / "public" / "wre-sentinel-impl-gsib-eval.html"
OUT.parent.mkdir(parents=True, exist_ok=True)
DOC = json.loads(SRC.read_text(encoding="utf-8"))


def e(x):
    return escape(str(x))


SKIP = (
    "mid", "sid", "svcid", "dmid", "epid", "piid", "rid", "evid", "rsid",
    "name", "service", "plane", "entity", "method", "path", "priority",
    "item", "phase", "milestone", "dimension", "title", "abstract", "content",
    "type", "language",
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
    return f"<div class='sec'><h4>{e(s['sid'])}. {e(s['title'])}</h4>{kv_pairs(s)}</div>"


def module_html(m):
    secs = "".join(section_html(s) for s in m["sections"])
    purpose = m.get("purpose") or ""
    return (
        f"<section class='module' id='{e(m['mid'])}'>"
        f"<h3>{e(m['mid'])} — {e(m['title'])}</h3>"
        f"<p class='sum'>{e(purpose)}</p>{secs}</section>"
    )


def list_array(arr, label_keys, anchor, title):
    rows = []
    for it in arr:
        head_parts = [e(it.get(label_keys[0], ""))] + [e(it.get(k, "")) for k in label_keys[1:]]
        head = " · ".join(p for p in head_parts if p)
        rows.append(f"<div class='card'><div class='card-head'>{head}</div>{kv_pairs(it)}</div>")
    return f"<section id='{anchor}'><h3>{title} ({len(arr)})</h3>{''.join(rows)}</section>"


distinctive = [
    ("wreServices",      "wre-services",      "WRE Services (M1)",                ["svcid", "service", "type"]),
    ("sentinelServices", "sentinel-services", "Sentinel Services (M3)",           ["svcid", "service", "plane"]),
    ("dataModels",       "data-models",       "Data Models (M2/M4)",              ["dmid", "entity"]),
    ("apiEndpoints",     "api-endpoints",     "API Endpoints (M4)",               ["epid", "method", "path"]),
    ("implPlanItems",    "impl-plan-items",   "Prioritized Plan Items P0-P3 (M5)", ["piid", "priority", "item"]),
    ("roadmapPhases",    "roadmap-phases",    "G-SIB 2026-2030 Roadmap (M6)",     ["rid", "phase", "milestone"]),
    ("evaluation",       "evaluation",        "Executive Critical Evaluation (M7)", ["evid", "dimension"]),
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


def table_rows(rows, cols):
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f"<td>{e(r.get(c, ''))}</td>" for c in cols) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def table_dict(d, key_label, val_label="value"):
    head = f"<tr><th>{e(key_label)}</th><th>{e(val_label)}</th></tr>"
    rows = []
    for k, v in d.items():
        if isinstance(v, dict):
            vstr = "; ".join(f"{kk}={vv}" for kk, vv in v.items())
        elif isinstance(v, list):
            vstr = "; ".join(json.dumps(x) if isinstance(x, dict) else str(x) for x in v)
        else:
            vstr = str(v)
        rows.append(f"<tr><td>{e(k)}</td><td>{e(vstr)}</td></tr>")
    return f"<table><thead>{head}</thead><tbody>{''.join(rows)}</tbody></table>"


report_full_html = (
    "<section id='report-sections-full'><h3>Whitepaper Sections — &lt;title&gt; / &lt;abstract&gt; / &lt;content&gt;</h3>"
    + "".join(
        f"<div class='card'><div class='card-head'>{e(rs['rsid'])} · {e(rs['title'])}</div>"
        f"<div class='kv'><b>abstract</b>: {e(rs['abstract'])}</div>"
        f"<div class='kv'><b>content</b>: {e(rs['content'])}</div></div>"
        for rs in DOC["reportSections"]
    )
    + "</section>"
)

schemas_html = f"<section id='schemas'><h3>Schemas ({len(DOC['schemas'])})</h3>{table_dict(DOC['schemas'], 'schema', 'fields')}</section>"
code_html = (
    "<section id='code'><h3>Code &amp; Artifacts (Rego / YAML / OpenAPI / SQL)</h3>"
    + "".join(
        f"<div class='kv'><b>{e(k)}</b><ul>" + "".join(f"<li><pre>{e(item)}</pre></li>" for item in v) + "</ul></div>"
        for k, v in DOC["code"].items()
    )
    + "</section>"
)
kpis_html = f"<section id='kpis'><h3>KPIs / Indices ({len(DOC['kpis'])})</h3>{table_dict(DOC['kpis'], 'index', 'target/cadence')}</section>"
rcm_html = f"<section id='rcm'><h3>Risk Control Matrix ({len(DOC['riskControlMatrix'])})</h3>{table_rows(DOC['riskControlMatrix'], ['risk','control','owner','evidence'])}</section>"
trace_html = f"<section id='trace'><h3>Traceability ({len(DOC['traceability'])})</h3>{table_rows(DOC['traceability'], ['from','to','via'])}</section>"
flows_html = f"<section id='data-flows'><h3>Data Flows ({len(DOC['dataFlows'])})</h3>{table_rows(DOC['dataFlows'], ['flow'])}</section>"
regs_html = f"<section id='regulators'><h3>Regulators ({len(DOC['regulators'])})</h3>{table_rows(DOC['regulators'], ['name','scope'])}</section>"
rollout_html = f"<section id='rollout-90'><h3>90-Day Rollout ({len(DOC['rollout90'])})</h3>{table_rows(DOC['rollout90'], ['day','task'])}</section>"
evidence_html = (
    f"<section id='evidence-pack'><h3>Regulator Evidence Pack ({len(DOC['evidencePack'])})</h3>"
    + "<ul>" + "".join(f"<li>{e(x)}</li>" for x in DOC["evidencePack"]) + "</ul></section>"
)

tail_html = schemas_html + code_html + kpis_html + rcm_html + trace_html + flows_html + regs_html + rollout_html + evidence_html


exs = DOC["executiveSummary"]
exec_html = f"""
<section id='exec'><h3>Executive Summary</h3>
<p><b>Headline:</b> {e(exs['headline'])}</p>
<p><b>Scope:</b> {e(exs['scope'])}</p>
<p><b>Investment:</b> {e(exs['investment'])}</p>
<p><b>Target Indices:</b> {e(exs['targetIndices'])}</p>
<p><b>Board Recommendation:</b> {e(exs['recommendation'])}</p>
<div class='kv'><b>Differentiators</b><ul>{''.join(f'<li>{e(x)}</li>' for x in exs['differentiators'])}</ul></div>
</section>
"""


directive = DOC["directive"]
indices_rows = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in DOC["indices"].items())
prio_rows = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in DOC["priorities"].items())
invest = DOC["investment"]
invest_breakdown = "".join(f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in invest["breakdown"].items())
audiences_list = "".join(f"<li>{e(a)}</li>" for a in DOC["audiences"])

meta_html = f"""
<section id='directive'><h3>Strategic Directive</h3>
<p><b>Scope:</b> {e(directive['scope'])}</p>
<div class='kv'><b>Outcomes</b><ul>{''.join(f'<li>{e(x)}</li>' for x in directive['outcomes'])}</ul></div>
<div class='kv'><b>Do NOT</b><ul>{''.join(f'<li>{e(x)}</li>' for x in directive['doNot'])}</ul></div>
</section>

<section id='audiences'><h3>Intended Audiences ({len(DOC['audiences'])})</h3><ul>{audiences_list}</ul></section>

<section id='indices'><h3>Performance Indices ({len(DOC['indices'])})</h3><ul>{indices_rows}</ul></section>

<section id='priorities'><h3>Priority Levels (P0-P3)</h3><ul>{prio_rows}</ul></section>

<section id='investment'><h3>Investment Envelope</h3>
<p><b>Total Range:</b> {e(invest['totalRange'])} · <b>Window:</b> {e(invest['programWindow'])} · <b>Currency:</b> {e(invest['currency'])}</p>
<div class='kv'><b>Breakdown</b><ul>{invest_breakdown}</ul></div>
</section>
"""


html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
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
pre {{ background:#0a0f15; border:1px solid var(--line); border-radius:4px; padding:8px; font-size:11px; overflow-x:auto; color:#d0d7de; margin:0; white-space:pre-wrap; }}
.counts {{ display:flex; flex-wrap:wrap; gap:10px; margin:14px 0; }}
.counts span {{ background:#0e141b; border:1px solid var(--line); padding:4px 10px; border-radius:14px; font-size:12px; color:var(--muted); }}
.counts span b {{ color:var(--acc); }}
code {{ background:#0e141b; padding:1px 4px; border-radius:3px; font-size:12px; }}
@media (max-width:900px) {{ .layout {{ grid-template-columns:1fr; }} nav.toc {{ position:relative; height:auto; }} main {{ padding:20px; }} }}
</style>
</head><body>
<header>
<h1>{e(DOC['title'])}</h1>
<div class="meta">docRef <b>{e(DOC['docRef'])}</b> · v{e(DOC['version'])} · {e(DOC['status'])}</div>
<div class="meta">{e(DOC['classification'])}</div>
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
<li><a href='#audiences'>Audiences</a></li>
<li><a href='#indices'>Indices</a></li>
<li><a href='#priorities'>Priorities P0-P3</a></li>
<li><a href='#investment'>Investment</a></li>
</ul>
<h4>Modules (M1-M8)</h4>
<ul>{toc_modules}</ul>
<h4>Specs & Plan</h4>
<ul>{toc_distinct}</ul>
<h4>Whitepaper & Tables</h4>
<ul>
<li><a href='#report-sections-full'>Whitepaper Sections</a></li>
<li><a href='#schemas'>Schemas</a></li>
<li><a href='#code'>Code &amp; Artifacts</a></li>
<li><a href='#kpis'>KPIs</a></li>
<li><a href='#rcm'>Risk Control Matrix</a></li>
<li><a href='#trace'>Traceability</a></li>
<li><a href='#data-flows'>Data Flows</a></li>
<li><a href='#regulators'>Regulators</a></li>
<li><a href='#rollout-90'>90-Day Rollout</a></li>
<li><a href='#evidence-pack'>Evidence Pack</a></li>
</ul>
</nav>
<main>
{exec_html}
{meta_html}
{modules_html}
{distinctive_html}
{report_full_html}
{tail_html}
</main>
</div>
</body></html>
"""

OUT.write_text(html, encoding="utf-8")
print(f"WP-063 HTML written: {OUT} ({OUT.stat().st_size} bytes)")
