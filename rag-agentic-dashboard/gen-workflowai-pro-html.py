#!/usr/bin/env python3
"""
WORKFLOWAI-PRO-WP-033 — HTML Dashboard Renderer
Generates: public/workflowai-pro.html
"""

import json
import html as htmllib
from pathlib import Path

HERE = Path(__file__).parent
SRC = HERE / "data" / "workflowai-pro.json"
OUT = HERE / "public" / "workflowai-pro.html"


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
            return f"<table class='grid'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
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
        html.append(f"<div class='sub'><h4>{esc(key)}</h4>{render_value(val)}</div>")
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

    modules = [
        data["m1_architecture"], data["m2_strategy"], data["m3_agi"],
        data["m4_reports"], data["m5_prompt"], data["m6_agents"],
        data["m7_orchestrator"], data["m8_taxonomy"], data["m9_incident"],
        data["m10_backend"], data["m11_experience"], data["m12_implementation"],
    ]

    toc_items = "".join(
        f"<li><a href='#{esc(m['id'])}'>{esc(m['id'])} · {esc(m['title'])}</a></li>"
        for m in modules
    )
    toc_items += (
        "<li><a href='#opa-policies'>OPA Policies</a></li>"
        "<li><a href='#indices'>Indices & KPIs</a></li>"
        "<li><a href='#case-studies'>Case Studies</a></li>"
        "<li><a href='#schemas'>Schemas</a></li>"
        "<li><a href='#code-examples'>Code Examples</a></li>"
        "<li><a href='#api'>API Endpoints</a></li>"
    )

    modules_html = "\n".join(render_module(m) for m in modules)

    opa_rows = "".join(
        f"<tr><td>{esc(p['id'])}</td><td>{esc(p['name'])}</td><td>{esc(p['enforce'])}</td></tr>"
        for p in data["opaPolicies"]
    )

    idx_rows = "".join(
        f"<tr><td>{esc(i['id'])}</td><td>{esc(i['name'])}</td><td>{esc(i['range'])}</td><td>{esc(i['target'])}</td></tr>"
        for i in data["indices"]
    )

    cs_html = ""
    for cs in data["caseStudies"]:
        cs_html += (
            f"<div class='case'><h3>{esc(cs['id'])} · {esc(cs['title'])}</h3>"
            f"<p><strong>Sector:</strong> {esc(cs['sector'])}</p>"
            f"<p>{esc(cs['summary'])}</p>"
            f"<div class='sub'><h4>Outcomes</h4>{kv_table(cs['outcomes'])}</div>"
            "</div>"
        )

    schemas_html = ""
    for name, sch in data["schemas"].items():
        schemas_html += (
            f"<details><summary>{esc(name)}</summary>"
            f"<pre><code>{esc(json.dumps(sch, indent=2))}</code></pre></details>"
        )

    code_html = ""
    for name, code in data["codeExamples"].items():
        code_html += (
            f"<details><summary>{esc(name)}</summary>"
            f"<pre><code>{esc(code)}</code></pre></details>"
        )

    api = data["apiEndpoints"]
    api_items = "".join(
        f"<li><code>{esc(api['prefix'])}{esc(r)}</code></li>" for r in api["routes"]
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>{esc(meta['docRef'])} — {esc(meta['title'])}</title>
<meta name="description" content="{esc(meta['subtitle'])}" />
<style>
  :root {{
    --bg: #0b1020; --panel:#111a34; --fg:#e8edf7; --muted:#8aa0c2;
    --accent:#7cc6ff; --accent2:#b693ff; --line:#1d2a52; --ok:#58f0a7; --warn:#ffcb6b;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Inter,sans-serif; }}
  header.hero {{ padding:32px 36px; background:linear-gradient(135deg,#121a3a,#0b1020);
                 border-bottom:1px solid var(--line); }}
  header.hero h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.2px; }}
  header.hero .subtitle {{ color:var(--muted); max-width:1100px; }}
  header.hero .badges {{ margin-top:14px; display:flex; gap:8px; flex-wrap:wrap; }}
  header.hero .badge {{ background:#19255a; color:var(--accent); padding:4px 10px;
                       border-radius:999px; font-size:12px; border:1px solid var(--line); }}
  nav.toc {{ position:sticky; top:0; background:#0b1020ee; backdrop-filter:blur(8px);
             border-bottom:1px solid var(--line); padding:10px 20px; z-index:5; }}
  nav.toc ul {{ list-style:none; margin:0; padding:0; display:flex; flex-wrap:wrap; gap:6px; }}
  nav.toc li a {{ color:var(--accent); text-decoration:none; padding:4px 10px;
                  border:1px solid var(--line); border-radius:6px; font-size:12px; }}
  nav.toc li a:hover {{ background:#141e44; }}
  main {{ padding:24px 36px 80px; max-width:1280px; }}
  section.module {{ background:var(--panel); border:1px solid var(--line);
                    border-radius:12px; padding:22px 24px; margin:20px 0; }}
  section.module h2 {{ margin:0 0 8px; color:var(--accent2); font-size:18px; }}
  section.module .summary {{ color:var(--muted); margin:0 0 16px; }}
  .section {{ border-top:1px dashed var(--line); padding-top:14px; margin-top:14px; }}
  .section h3 {{ margin:0 0 8px; font-size:15px; color:var(--accent); }}
  .section .sub {{ margin:10px 0; }}
  .section .sub h4 {{ margin:0 0 6px; font-size:13px; color:var(--muted);
                      text-transform:uppercase; letter-spacing:.5px; }}
  table.kv, table.grid {{ width:100%; border-collapse:collapse; font-size:13px;
                          background:#0d1532; border:1px solid var(--line); border-radius:6px; overflow:hidden; }}
  table.kv td, table.grid td, table.grid th {{ padding:6px 10px; border-bottom:1px solid var(--line);
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
  footer {{ color:var(--muted); border-top:1px solid var(--line);
            padding:16px 36px; font-size:12px; }}
</style>
</head>
<body>
<header class="hero">
  <h1>{esc(meta['docRef'])} — {esc(meta['title'])}</h1>
  <p class="subtitle">{esc(meta['subtitle'])}</p>
  <div class="badges">
    <span class="badge">Version {esc(meta['version'])}</span>
    <span class="badge">Horizon {esc(meta['horizon'])}</span>
    <span class="badge">{esc(meta['productName'])}</span>
    <span class="badge">{esc(meta['productTier'])}</span>
  </div>
</header>
<nav class="toc"><ul id="api-list">{toc_items}</ul></nav>
<main>
  <section class="module" id="exec">
    <h2>Executive Summary</h2>
    {kv_table(exec_sum)}
  </section>

  <section class="module" id="meta">
    <h2>Document Metadata</h2>
    {kv_table(meta)}
  </section>

  {modules_html}

  <section class="module" id="opa-policies">
    <h2>OPA / Rego Policies</h2>
    <table class="grid"><thead><tr><th>ID</th><th>Name</th><th>Enforcement</th></tr></thead>
    <tbody>{opa_rows}</tbody></table>
  </section>

  <section class="module" id="indices">
    <h2>Governance Indices & KPIs</h2>
    <table class="grid"><thead><tr><th>ID</th><th>Name</th><th>Range</th><th>Target</th></tr></thead>
    <tbody>{idx_rows}</tbody></table>
  </section>

  <section class="module" id="case-studies">
    <h2>Case Studies</h2>
    {cs_html}
  </section>

  <section class="module" id="schemas">
    <h2>JSON Schemas</h2>
    {schemas_html}
  </section>

  <section class="module" id="code-examples">
    <h2>Code Examples</h2>
    {code_html}
  </section>

  <section class="module" id="api">
    <h2>API Endpoints (planned)</h2>
    <p class="summary">Prefix: <code>{esc(api['prefix'])}</code></p>
    <ul>{api_items}</ul>
  </section>
</main>
<footer>
  © {esc(meta['docRef'])} v{esc(meta['version'])} · {esc(meta['date'])} ·
  {esc(meta['classification'])}
</footer>
</body>
</html>
"""
    OUT.write_text(page, encoding="utf-8")
    size_kb = OUT.stat().st_size // 1024
    print(f"Wrote {OUT} ({size_kb} KB)")
    print(f"Modules rendered: {len(modules)} | Case studies: {len(data['caseStudies'])} | "
          f"OPA policies: {len(data['opaPolicies'])} | Indices: {len(data['indices'])}")


if __name__ == "__main__":
    main()
