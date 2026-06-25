# Sentinel OSCAL tooling

Machine-readable control catalogs (OSCAL 1.1.2) plus the tools that keep them
honest and turn them into regulator deliverables.

## Files

| File | Purpose |
|------|---------|
| `catalog_sentinel_v24_excerpt.json` | OSCAL 1.1.2 catalog — Containment (CON) + Cryptographic-evidence (CRY) controls, with regime back-matter. |
| `catalog_sentinel_v24_env_rte.json` | OSCAL 1.1.2 catalog — Confidential-computing (ENV) + MoE-routing (RTE) controls, with regime back-matter. |
| `sentinel_control_catalog_v1.yaml` | Higher-level control families + regulatory mapping (legacy/companion view). |
| `oscal_conformance.py` | **Conformance validator** — verifies every control's `tla-spec` / `rego-policy` / `circuit` / `simulator` prop resolves to a real in-repo artifact, every regime `#href` resolves to a back-matter anchor, `feasibility-tier ∈ {A,B,C,D}`, and `freshness-sla` is a valid ISO-8601 duration. |
| `annex_iv_section_map.yaml` | Auditable map: each EU AI Act Annex IV section (A–H) → the OSCAL control ids that evidence it, plus a provider narrative. |
| `generate_annex_iv_dossier.py` | **Dossier generator** — auto-assembles an OSCAL-native Annex IV technical-documentation dossier from the catalogs + live assurance evidence. |
| `generated/annex_iv_dossier.{json,md}` | Sample auto-assembled dossier (regenerate any time; `generated_at` changes per run). |

## Run it

```bash
# 1. Verify catalog cross-reference integrity (43 checks; falsifiable)
python3 governance_artifacts/oscal/oscal_conformance.py            # human
python3 governance_artifacts/oscal/oscal_conformance.py --json     # machine

# 2. Assemble the Annex IV dossier with LIVE evidence (re-runs backing checks)
python3 governance_artifacts/oscal/generate_annex_iv_dossier.py
#   -> generated/annex_iv_dossier.json  (machine-readable)
#   -> generated/annex_iv_dossier.md    (human-readable)

# Faster, assembly-only (does NOT run backing checks; no section reported SATISFIED)
python3 governance_artifacts/oscal/generate_annex_iv_dossier.py --no-verify
```

Both tools are wired into `governance_artifacts/run_runnable_assurance.sh`
(steps 12 and 13) and into CI.

## Evidence-status semantics (honesty model)

The dossier never marks a section satisfied on prose alone:

| Status | Meaning |
|--------|---------|
| `SATISFIED` | ≥1 mapped control whose **runnable** assurance check passed in this run. |
| `PARTIAL` | Has runnable-backed controls but none passed in this run. |
| `PENDING-EVIDENCE` | Mapped only to organisational / hardware-dependent evidence not yet attached (e.g. `env-02` enclave key custody), or no controls mapped. |

`generate_annex_iv_dossier.py` **refuses to run** if the catalog is not conformant
or if `annex_iv_section_map.yaml` references a control id that does not exist in
any catalog — so the dossier can only ever be built from real, resolvable controls.

## Integrity statement

These artifacts verify **assembly integrity** — that the dossier is built only
from real controls and currently-passing checks. They are **not** a conformity
assessment and do **not** assert that the institution is compliant with the EU AI
Act. Feasibility tiers (A verified now / B needs hardware / C 2026–2030 standards /
D speculative 2030–2035) are carried through to the dossier verbatim.
