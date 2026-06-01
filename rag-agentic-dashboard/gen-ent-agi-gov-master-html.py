#!/usr/bin/env python3
"""
ENT-AGI-GOV-MASTER-WP-035 — HTML Dashboard Renderer
Generates: public/ent-agi-gov-master.html
"""

import json
import html as htmllib
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE / "data" / "ent-agi-gov-master.json"
OUT = HERE / "public" / "ent-agi-gov-master.html"

MODULE_ORDER = [
    "M1_pillars",
    "M2_regulatory",
    "M3_architectures",
    "M4_safety",
    "M5_civilizational",
    "M6_financialMrm",
    "M7_kafkaGac",
    "M8_roadmap",
]


def esc(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return htmllib.escape(str(v))


def kv_table(d):
    rows = "".join(
        f"<tr><td class='k'>{esc(k)}</td><td class='v'>{render_value(v)}</td></tr>"
        for k, v in d.items()
    )
    return f"<table class='kv'>{rows}</table>"


def render_value(v):
    if isinstance(v, dict):
        return kv_table(v)
    if isinstance(v, list):
        if not v:
            return "<em>—</em>"
        if all(isinstance(x, (str, int, float, bool)) for x in v):
            return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in v) + "</ul>"
        if all(isinstance(x, dict) for x in v):
            keys = []
            for d in v:
                for k in d.keys():
                    if k not in keys:
                        keys.append(k)
            head = "".join(f"<th>{esc(k)}</th>" for k in keys)
            body = ""
            for d in v:
                body += "<tr>" + "".join(
                    f"<td>{render_value(d.get(k, ''))}</td>" for k in keys
                ) + "</tr>"
            return (
                f"<table class='grid'><thead><tr>{head}</tr></thead>"
                f"<tbody>{body}</tbody></table>"
            )
        return "<ul>" + "".join(f"<li>{render_value(x)}</li>" for x in v) + "</ul>"
    return esc(v)


def render_section(sec):
    sid = sec.get("id", "")
    title = sec.get("title", "")
    html = [f"<div class='section' id='{esc(sid)}'>"]
    html.append(f"<h3>{esc(sid)} · {esc(title)}</h3>")
    for key, val in sec.items():
        if key in ("id", "title"):
            continue
        html.append(
            f"<div class='sub'><h4>{esc(key)}</h4>{render_value(val)}</div>"
        )
    html.append("</div>")
    return "\n".join(html)


def render_module(mod):
    mid = mod.get("id", "")
    title = mod.get("title", "")
    summary = mod.get("summary", "")
    sections = mod.get("sections", []) or []
    html = [f"<section class='module' id='{esc(mid)}'>"]
    html.append(f"<h2>{esc(mid)} · {esc(title)}</h2>")
    if summary:
        html.append(f"<p class='summary'>{esc(summary)}</p>")
    for sec in sections:
        html.append(render_section(sec))
    html.append("</section>")
    return "\n".join(html)


def main():
    data = json.loads(SRC.read_text(encoding="utf-8"))
    meta = data["meta"]
    exec_sum = data["executiveSummary"]

    modules = [data[k] for k in MODULE_ORDER if k in data]

    toc_items = "".join(
        f"<li><a href='#{esc(m['id'])}'>{esc(m['id'])} · {esc(m['title'].split('—')[-1].strip()[:46])}</a></li>"
        for m in modules
    )
    toc_items += (
        "<li><a href='#schemas'>Schemas</a></li>"
        "<li><a href='#code-examples'>Code Examples</a></li>"
        "<li><a href='#case-studies'>Case Studies</a></li>"
        "<li><a href='#regulatory-matrix'>Regulatory Alignment</a></li>"
        "<li><a href='#api'>API Endpoints</a></li>"
    )

    modules_html = "\n".join(render_module(m) for m in modules)

    schemas_html = ""
    for name, sch in data.get("schemas", {}).items():
        schemas_html += (
            f"<details><summary>{esc(name)}</summary>"
            f"<pre><code>{esc(json.dumps(sch, indent=2))}</code></pre></details>"
        )

    code_html = ""
    for name, code in data.get("codeExamples", {}).items():
        code_html += (
            f"<details><summary>{esc(name)}</summary>"
            f"<pre><code>{esc(code)}</code></pre></details>"
        )

    cs_html = ""
    for cs in data.get("caseStudies", []):
        outcomes = cs.get("outcomes", {})
        outcomes_html = (
            kv_table(outcomes) if isinstance(outcomes, dict)
            else render_value(outcomes)
        )
        cs_html += (
            f"<div class='case'><h3>{esc(cs.get('id',''))} · {esc(cs.get('title',''))}</h3>"
            f"<p><strong>Sector:</strong> {esc(cs.get('sector',''))}</p>"
            f"<p>{esc(cs.get('summary',''))}</p>"
            f"<div class='sub'><h4>Outcomes</h4>{outcomes_html}</div>"
            "</div>"
        )

    reg = meta.get("regulatoryAlignment", [])
    if isinstance(reg, list):
        reg_html = "<ul>" + "".join(f"<li>{esc(r)}</li>" for r in reg) + "</ul>"
    else:
        reg_html = esc(reg)

    audience = meta.get("audience", [])
    audience_html = (
        "<ul>" + "".join(f"<li>{esc(a)}</li>" for a in audience) + "</ul>"
        if isinstance(audience, list) else esc(audience)
    )

    horizon = meta.get("horizonMilestones", {})
    horizon_html = kv_table(horizon) if isinstance(horizon, dict) else esc(horizon)

    inv = meta.get("deliverableInventory", {})
    inv_html = kv_table(inv) if isinstance(inv, dict) else esc(inv)

    api = data.get("apiEndpoints", {"prefix": "/api/ent-agi-gov-master", "routes": []})
    api_items = "".join(
        f"<li><code>{esc(api['prefix'])}{esc(r)}</code></li>"
        for r in api.get("routes", [])
    )

    n_modules = len(modules)
    total_sections = sum(len(m.get("sections", []) or []) for m in modules)
    n_schemas = len(data.get("schemas", {}))
    n_code = len(data.get("codeExamples", {}))
    n_cs = len(data.get("caseStudies", []))
    n_routes = len(api.get("routes", []))

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{esc(meta.get('docRef',''))} — {esc(meta.get('title',''))}</title>
<meta name="description" content="{esc(meta.get('subtitle',''))}" />
<style>
  :root {{
    --bg:#070b1a; --panel:#0f1734; --panel2:#121d40; --fg:#eaf0fb; --muted:#8aa0c2;
    --accent:#7cc6ff; --accent2:#b693ff; --accent3:#ff9ec7; --line:#1d2a52;
    --ok:#58f0a7; --warn:#ffcb6b; --crit:#ff7a7a;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif; }}
  header.hero {{ padding:34px 38px;
                 background:linear-gradient(135deg,#1a2566,#0a1235 55%,#070b1a);
                 border-bottom:1px solid var(--line); }}
  header.hero .doc-ref {{ color:var(--accent3); font-size:12px; letter-spacing:1px;
                           text-transform:uppercase; margin-bottom:6px; }}
  header.hero h1 {{ margin:0 0 10px; font-size:25px; letter-spacing:.2px; }}
  header.hero .subtitle {{ color:var(--muted); max-width:1100px; }}
  header.hero .badges {{ margin-top:16px; display:flex; gap:8px; flex-wrap:wrap; }}
  header.hero .badge {{ background:#19255a; color:var(--accent); padding:5px 12px;
                       border-radius:999px; font-size:12px; border:1px solid var(--line); }}
  header.hero .badge.warn {{ color:var(--warn); border-color:#5a3f1a; background:#2a1f0d; }}
  header.hero .badge.ok {{ color:var(--ok); border-color:#1a4a31; background:#0c2a1c; }}
  header.hero .kpis {{ margin-top:18px; display:flex; gap:18px; flex-wrap:wrap; }}
  header.hero .kpi {{ background:#0d1532; border:1px solid var(--line); border-radius:10px;
                      padding:10px 14px; min-width:130px; }}
  header.hero .kpi .v {{ font-size:20px; color:var(--accent2); font-weight:600; }}
  header.hero .kpi .l {{ font-size:11px; color:var(--muted); text-transform:uppercase;
                          letter-spacing:.6px; }}
  nav.toc {{ position:sticky; top:0; background:#070b1aee; backdrop-filter:blur(8px);
             border-bottom:1px solid var(--line); padding:10px 20px; z-index:5; }}
  nav.toc ul {{ list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap; gap:6px; }}
  nav.toc li a {{ color:var(--accent); text-decoration:none; padding:4px 10px;
                  border:1px solid var(--line); border-radius:6px; font-size:12px; }}
  nav.toc li a:hover {{ background:#141e44; }}
  main {{ padding:24px 36px 80px; max-width:1340px; }}
  section.module {{ background:var(--panel); border:1px solid var(--line);
                    border-radius:12px; padding:22px 24px; margin:20px 0; }}
  section.module h2 {{ margin:0 0 8px; color:var(--accent2); font-size:18px; }}
  section.module .summary {{ color:var(--muted); margin:0 0 16px; }}
  .section {{ border-top:1px dashed var(--line); padding-top:14px; margin-top:14px; }}
  .section h3 {{ margin:0 0 8px; font-size:15px; color:var(--accent); }}
  .section .sub {{ margin:10px 0; }}
  .section .sub h4 {{ margin:0 0 6px; font-size:12px; color:var(--muted);
                      text-transform:uppercase; letter-spacing:.5px; }}
  table.kv, table.grid {{ width:100%; border-collapse:collapse; font-size:13px;
                          background:#0d1532; border:1px solid var(--line);
                          border-radius:6px; overflow:hidden; }}
  table.kv td, table.grid td, table.grid th {{ padding:6px 10px;
                                              border-bottom:1px solid var(--line);
                                              vertical-align:top; text-align:left; }}
  table.kv td.k {{ color:var(--muted); width:30%; white-space:nowrap; }}
  table.grid th {{ background:#162248; color:var(--accent); font-weight:600; }}
  ul {{ margin:6px 0 6px 20px; padding:0; }}
  code {{ background:#0d1532; padding:1px 5px; border-radius:4px; color:var(--accent); }}
  pre {{ background:#0d1532; padding:12px; border-radius:6px; overflow:auto;
         border:1px solid var(--line); font-size:12px; }}
  details {{ background:#0d1532; border:1px solid var(--line); border-radius:6px;
             padding:8px 12px; margin:8px 0; }}
  details summary {{ cursor:pointer; color:var(--accent); }}
  .case {{ border-top:1px dashed var(--line); padding-top:14px; margin-top:14px; }}
  .case h3 {{ margin:0 0 8px; color:var(--accent3); font-size:15px; }}
  footer {{ color:var(--muted); border-top:1px solid var(--line);
            padding:16px 36px; font-size:12px; }}
</style>
</head>
<body>
<header class="hero">
  <div class="doc-ref">{esc(meta.get('docRef',''))} · {esc(meta.get('classification',''))}</div>
  <h1>{esc(meta.get('title',''))}</h1>
  <p class="subtitle">{esc(meta.get('subtitle',''))}</p>
  <div class="badges">
    <span class="badge">Version {esc(meta.get('version',''))}</span>
    <span class="badge">Date {esc(meta.get('date',''))}</span>
    <span class="badge">Horizon {esc(meta.get('horizon',''))}</span>
    <span class="badge warn">EU AI Act</span>
    <span class="badge warn">SR 11-7 Tier 1</span>
    <span class="badge">NIST AI RMF 1.0</span>
    <span class="badge">ISO/IEC 42001</span>
    <span class="badge ok">Basel III/IV · ICAAP</span>
    <span class="badge ok">FCRA / ECOA</span>
  </div>
  <div class="kpis">
    <div class="kpi"><div class="v">{n_modules}</div><div class="l">Modules</div></div>
    <div class="kpi"><div class="v">{total_sections}</div><div class="l">Sections</div></div>
    <div class="kpi"><div class="v">7</div><div class="l">Pillars (G1-G7)</div></div>
    <div class="kpi"><div class="v">16</div><div class="l">Regulatory Axes</div></div>
    <div class="kpi"><div class="v">9</div><div class="l">Reference Architectures</div></div>
    <div class="kpi"><div class="v">8</div><div class="l">Safety Protocols</div></div>
    <div class="kpi"><div class="v">{n_schemas}</div><div class="l">Schemas</div></div>
    <div class="kpi"><div class="v">{n_code}</div><div class="l">Code Examples</div></div>
    <div class="kpi"><div class="v">{n_cs}</div><div class="l">Case Studies</div></div>
    <div class="kpi"><div class="v">{n_routes}</div><div class="l">API Routes</div></div>
  </div>
</header>
<nav class="toc"><ul>{toc_items}</ul></nav>
<main>
  <section class="module" id="exec">
    <h2>Executive Summary</h2>
    {kv_table(exec_sum)}
  </section>

  <section class="module" id="meta">
    <h2>Document Metadata</h2>
    {kv_table({k: v for k, v in meta.items()
               if k not in ('audience', 'regulatoryAlignment',
                            'horizonMilestones', 'deliverableInventory')})}
    <div class="section" id="audience">
      <h3>Audience</h3>
      {audience_html}
    </div>
    <div class="section" id="horizon">
      <h3>Horizon Milestones (2026-2030)</h3>
      {horizon_html}
    </div>
    <div class="section" id="inventory">
      <h3>Deliverable Inventory</h3>
      {inv_html}
    </div>
  </section>

  {modules_html}

  <section class="module" id="regulatory-matrix">
    <h2>Regulatory Alignment (Headline)</h2>
    <p class="summary">Master crosswalk lives in <code>M2 — Regulatory Alignment Matrix</code>; the headline list of 16 axes:</p>
    {reg_html}
  </section>

  <section class="module" id="schemas">
    <h2>JSON Schemas</h2>
    <p class="summary">{n_schemas} schemas covering governance artefacts, compute registry, model risk records, fairness reports, policy decisions, treaty disclosures.</p>
    {schemas_html}
  </section>

  <section class="module" id="code-examples">
    <h2>Code Examples</h2>
    <p class="summary">{n_code} reference implementations: OPA/Rego policies, Terraform GaC modules, Merkle WORM audit, CI/CD pipeline, governance sidecar, fairness gate, kinetic kill-switch, regulator report templates.</p>
    {code_html}
  </section>

  <section class="module" id="case-studies">
    <h2>Case Studies</h2>
    <p class="summary">{n_cs} reference deployments across G-SIFI, Fortune 500, Global 2000, asset management, frontier AI lab, and sovereign-cloud government tiers.</p>
    {cs_html}
  </section>

  <section class="module" id="api">
    <h2>API Endpoints</h2>
    <p class="summary">Prefix: <code>{esc(api.get('prefix',''))}</code> · Total planned: {n_routes}</p>
    <ul>{api_items}</ul>
  </section>
</main>
<footer>
  © {esc(meta.get('docRef',''))} v{esc(meta.get('version',''))} ·
  {esc(meta.get('date',''))} · {esc(meta.get('classification',''))} ·
  Owner: {esc(meta.get('owner',''))}
</footer>
</body>
</html>
"""
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    size_kb = OUT.stat().st_size // 1024
    print(f"Wrote {OUT} ({size_kb} KB)")
    print(
        f"Modules: {n_modules} | Sections: {total_sections} | "
        f"Schemas: {n_schemas} | Code: {n_code} | Cases: {n_cs} | "
        f"Routes: {n_routes}"
    )


if __name__ == "__main__":
    main()
