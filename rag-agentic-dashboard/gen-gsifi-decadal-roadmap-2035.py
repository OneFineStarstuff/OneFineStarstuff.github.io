#!/usr/bin/env python3
"""Decadal Roadmap for Enterprise AGI/ASI Governance (2026-2035) HTML renderer."""

import html
import json
from pathlib import Path

ROOT = Path(__file__).parent
SRC = ROOT / "data" / "gsifi-decadal-roadmap-2035.json"
OUT = ROOT / "public" / "gsifi-decadal-roadmap-2035.html"


def generate_html():
    """Main generation logic."""
    if not SRC.exists():
        print(f"Error: {SRC} not found")
        return

    data = json.loads(SRC.read_text())

    def esc(val):
        return html.escape(str(val)) if val is not None else ""

    def render_list(items):
        return "<ul>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>"

    phases_parts = []
    for phase in data["phases"]:
        part = f"""
        <div class="card">
            <div class="phase-header">
                <span class="phase-title">{esc(phase['name'])}</span>
                <span class="phase-period">{esc(phase['period'])}</span>
            </div>
            <h3>Key Milestones</h3>
            {render_list(phase['milestones'])}
            <h3>Technical Requirements</h3>
            {render_list(phase['technicalRequirements'])}
        </div>"""
        phases_parts.append(part)
    phases_html = "\n".join(phases_parts)

    reg_parts = []
    for key, val in data["regulatoryMapping"].items():
        reg_parts.append(f"<tr><th>{esc(key.replace('_', ' '))}</th><td>{esc(val)}</td></tr>")
    reg_html = "\n".join(reg_parts)

    spec_parts = []
    for key, val in data["technicalSpecs"].items():
        spec_parts.append(f"""
            <div class="spec-item">
                <span class="spec-label">{esc(key.replace('Plane', ' Plane').title())}</span>
                {esc(val)}
            </div>""")
    spec_html = "\n".join(spec_parts)

    tags_html = " ".join(
        [
            f'<span class="tag" style="background:rgba(255,255,255,0.2);color:white;">{esc(f)}</span>'
            for f in data["metadata"]["frameworks"]
        ]
    )

    full_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(data['metadata']['title'])}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6;
               color: #333; max-width: 1000px; margin: 0 auto; padding: 2rem; background: #f5f7f9; }}
        header {{ background: #1a365d; color: white; padding: 2rem; border-radius: 8px; margin-bottom: 2rem;
                  box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1 {{ margin: 0; font-size: 2rem; }}
        h2 {{ color: #2c5282; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; margin-top: 2rem; }}
        .card {{ background: white; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        .phase-header {{ display: flex; justify-content: space-between; align-items: center; background: #edf2f7;
                        padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; }}
        .phase-title {{ font-weight: bold; font-size: 1.2rem; color: #2d3748; }}
        .phase-period {{ font-family: monospace; background: #2d3748; color: white; padding: 0.2rem 0.6rem;
                         border-radius: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; color: #4a5568; font-weight: 600; width: 30%; }}
        .tag {{ display: inline-block; background: #ebf8ff; color: #2b6cb0; padding: 0.2rem 0.5rem; border-radius: 4px;
                font-size: 0.85rem; margin-right: 0.5rem; margin-bottom: 0.5rem; }}
        .spec-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; }}
        .spec-item {{ background: #fffaf0; border-left: 4px solid #ed8936; padding: 1rem; border-radius: 4px; }}
        .spec-label {{ font-weight: bold; color: #7b341e; display: block; margin-bottom: 0.25rem; }}
        footer {{ margin-top: 3rem; text-align: center; color: #718096; font-size: 0.9rem;
                  border-top: 1px solid #e2e8f0; padding-top: 1rem; }}
    </style>
</head>
<body>
    <header>
        <h1>{esc(data['metadata']['title'])}</h1>
        <p>Target: {esc(data['metadata']['target'])} | Version: {esc(data['metadata']['version'])}</p>
        <div>
            {tags_html}
        </div>
    </header>

    <section>
        <h2>Decadal Execution Phases</h2>
        {phases_html}
    </section>

    <section>
        <h2>Regulatory Mapping Matrix</h2>
        <div class="card">
            <table>
                {reg_html}
            </table>
        </div>
    </section>

    <section>
        <h2>Core Technical Specifications</h2>
        <div class="spec-grid">
            {spec_html}
        </div>
    </section>

    <footer>
        Generated by Sentinel AI Governance Stack v2.4 | &copy; 2026-2035 Omni-Sentinel Mesh
    </footer>
</body>
</html>
"""
    OUT.write_text(full_content)
    print(f"Successfully generated {OUT}")


if __name__ == "__main__":
    generate_html()
