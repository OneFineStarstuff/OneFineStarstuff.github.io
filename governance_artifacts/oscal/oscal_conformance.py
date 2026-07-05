#!/usr/bin/env python3
"""
OSCAL catalog conformance validator — Sentinel v2.4 compliance-as-code integrity.

Compliance-as-code only delivers assurance if the catalog's machine-readable
cross-references actually resolve. A catalog can be valid JSON and still rot:
a `tla-spec` prop pointing at a TLA+ module that was renamed, a `rego-policy`
pointing at a deleted package, a `circuit` logical name with no circom file,
or an internal `#href` regime link that resolves to nothing. Each of those is a
silent gap between "what the control claims is verified" and "what is actually
in the repo".

This validator closes that gap. For every control in every OSCAL catalog under
governance_artifacts/oscal/ it checks:

  C1  Structural shape           OSCAL 1.1.2 catalog/metadata/groups/controls,
                                 each control has id + statement part.
  C2  Feasibility tier vocab     feasibility-tier prop in {A,B,C,D}.
  C3  Freshness-SLA format       freshness-sla is an ISO-8601 duration, or a
                                 "periodic/retest" pair "P.../P..." .
  C4  tla-spec resolution        prop value (module, optionally "Module::label")
                                 maps to an existing .tla file under tla/.
  C5  rego-policy resolution     prop "sentinel.attestation"-style package maps
                                 to a real package declared in some .rego file.
  C6  circuit resolution         logical circuit id (e.g. SRC-1) maps via the
                                 registry to an existing .circom file.
  C7  simulator resolution       simulator path exists on disk.
  C8  internal href resolution   every link href "#anchor" resolves to a
                                 back-matter resource uuid (no dangling regime
                                 references).

Exit non-zero if any check fails. `--json` emits a machine-readable report.

This is a Tier-A artifact: it verifies in-repo cross-reference integrity. It does
NOT assert that the named regimes are satisfied in production — only that the
catalog's claims are internally consistent and anchored to real artifacts.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Resolve repo-relative directories from this file's location:
# governance_artifacts/oscal/oscal_conformance.py
OSCAL_DIR = Path(__file__).resolve().parent
GA_DIR = OSCAL_DIR.parent                      # governance_artifacts/
REPO_ROOT = GA_DIR.parent                      # repo root
TLA_DIR = GA_DIR / "tla"
REGO_DIR = GA_DIR / "rego"
ZK_CIRCUITS = GA_DIR / "zk" / "circuits"

VALID_TIERS = {"A", "B", "C", "D"}

# Logical circuit-id -> circom file (relative to zk/circuits). Keeps catalogs
# referring to stable logical names while the physical filename can evolve.
CIRCUIT_REGISTRY = {
    "SRC-1": "src1_concentration_bound.circom",
    "SRC-FAIR-1": "src_fair1_reason_code_check.circom",
}

# ISO-8601 duration (subset sufficient for SLAs): PnYnMnDTnHnMnS / PnW.
_ISO_DUR = re.compile(
    r"^P(?:\d+W|(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?)$"
)


@dataclass
class CheckResult:
    check: str
    catalog: str
    control: str
    ok: bool
    detail: str


@dataclass
class Report:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, check, catalog, control, ok, detail):
        self.results.append(CheckResult(check, catalog, control, ok, detail))

    @property
    def failed(self):
        return [r for r in self.results if not r.ok]

    @property
    def passed(self):
        return [r for r in self.results if r.ok]


def _iso_duration_ok(value: str) -> bool:
    if value == "P":
        return False
    # Allow a "periodic/retest" pair like P1D/P90D.
    parts = value.split("/")
    return all(bool(_ISO_DUR.match(p)) for p in parts) and all(parts)


def _props(control: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in control.get("props", [])}


def _iter_controls(catalog: dict):
    """Yield (control_dict) walking nested groups."""
    def walk(groups):
        for g in groups:
            for c in g.get("controls", []):
                yield c
            yield from walk(g.get("groups", []))
    yield from walk(catalog.get("groups", []))


def _tla_modules() -> set[str]:
    return {p.stem for p in TLA_DIR.rglob("*.tla")}


def _rego_packages() -> set[str]:
    pkgs: set[str] = set()
    pat = re.compile(r"^\s*package\s+([A-Za-z0-9_.]+)", re.MULTILINE)
    for p in REGO_DIR.rglob("*.rego"):
        for m in pat.finditer(p.read_text(encoding="utf-8", errors="ignore")):
            pkgs.add(m.group(1))
    return pkgs


def validate_catalog(path: Path, rep: Report,
                     tla_mods: set[str], rego_pkgs: set[str]) -> None:
    name = path.name
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        rep.add("C1-structure", name, "-", False, f"invalid JSON: {e}")
        return

    cat = doc.get("catalog")
    if not isinstance(cat, dict):
        rep.add("C1-structure", name, "-", False, "missing top-level 'catalog'")
        return

    md = cat.get("metadata", {})
    ov = md.get("oscal-version")
    rep.add("C1-structure", name, "-", ov == "1.1.2",
            f"oscal-version={ov!r} (expected 1.1.2)")

    # Build back-matter anchor set (uuids + explicit 'anchor' props).
    anchors: set[str] = set()
    for res in cat.get("back-matter", {}).get("resources", []):
        if res.get("uuid"):
            anchors.add(res["uuid"])
        for pr in res.get("props", []):
            if pr.get("name") == "anchor":
                anchors.add(pr["value"])

    controls = list(_iter_controls(cat))
    if not controls:
        rep.add("C1-structure", name, "-", False, "no controls found")
        return

    for c in controls:
        cid = c.get("id", "<no-id>")

        # C1: id + statement part
        has_stmt = any(p.get("name") == "statement" and p.get("prose")
                       for p in c.get("parts", []))
        rep.add("C1-structure", name, cid, bool(c.get("id")) and has_stmt,
                "id+statement present" if has_stmt else "missing id or statement part")

        props = _props(c)

        # C2: feasibility tier vocabulary
        tier = props.get("feasibility-tier")
        if tier is not None:
            rep.add("C2-tier", name, cid, tier in VALID_TIERS,
                    f"feasibility-tier={tier!r}")
        else:
            rep.add("C2-tier", name, cid, False, "missing feasibility-tier prop")

        # C3: freshness-sla format (only if present)
        sla = props.get("freshness-sla")
        if sla is not None:
            rep.add("C3-sla", name, cid, _iso_duration_ok(sla),
                    f"freshness-sla={sla!r}")

        # C4: tla-spec resolution
        tla = props.get("tla-spec")
        if tla is not None:
            module = tla.split("::", 1)[0]
            rep.add("C4-tla", name, cid, module in tla_mods,
                    f"tla-spec={tla!r} -> module {module!r} "
                    + ("found" if module in tla_mods else "MISSING"))

        # C5: rego-policy resolution
        rego = props.get("rego-policy")
        if rego is not None:
            ok = rego in rego_pkgs
            rep.add("C5-rego", name, cid, ok,
                    f"rego-policy={rego!r} "
                    + ("found" if ok else f"MISSING (known: {sorted(rego_pkgs)})"))

        # C6: circuit resolution via registry
        circ = props.get("circuit")
        if circ is not None:
            fn = CIRCUIT_REGISTRY.get(circ)
            ok = bool(fn) and (ZK_CIRCUITS / fn).is_file()
            rep.add("C6-circuit", name, cid, ok,
                    f"circuit={circ!r} -> "
                    + (f"{fn} found" if ok else "UNRESOLVED (not in registry or file missing)"))

        # C7: simulator path resolution
        sim = props.get("simulator")
        if sim is not None:
            target = GA_DIR / sim
            rep.add("C7-simulator", name, cid, target.is_file(),
                    f"simulator={sim!r} "
                    + ("found" if target.is_file() else "MISSING"))

        # C8: internal href resolution
        for link in c.get("links", []):
            href = link.get("href", "")
            if href.startswith("#"):
                anchor = href[1:]
                rep.add("C8-href", name, cid, anchor in anchors,
                        f"link {link.get('rel','?')} -> #{anchor} "
                        + ("resolves" if anchor in anchors else "DANGLING"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="OSCAL catalog conformance validator")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("--dir", default=str(OSCAL_DIR),
                    help="directory of OSCAL catalog *.json files")
    args = ap.parse_args(argv)

    oscal_dir = Path(args.dir)
    catalogs = sorted(p for p in oscal_dir.glob("*.json"))
    rep = Report()

    if not catalogs:
        print(f"ERROR: no OSCAL catalog JSON files in {oscal_dir}", file=sys.stderr)
        return 2

    tla_mods = _tla_modules()
    rego_pkgs = _rego_packages()

    for path in catalogs:
        validate_catalog(path, rep, tla_mods, rego_pkgs)

    if args.json:
        print(json.dumps({
            "passed": len(rep.passed),
            "failed": len(rep.failed),
            "results": [asdict(r) for r in rep.results],
        }, indent=2))
    else:
        for r in rep.results:
            mark = "PASS" if r.ok else "FAIL"
            print(f"  [{mark}] {r.check:<14} {r.catalog} :: {r.control:<10} {r.detail}")
        print("-" * 70)
        print(f"OSCAL conformance: {len(rep.passed)} passed, {len(rep.failed)} failed "
              f"across {len(catalogs)} catalog(s)")

    return 1 if rep.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
