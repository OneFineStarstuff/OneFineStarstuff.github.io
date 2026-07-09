#!/usr/bin/env python3
"""
Recipient-side verifier for the Sentinel v2.4 distribution bundle.

This is the missing half of the packaging story (17th assurance check).
`package_distribution_bundle.py` PRODUCES a tamper-evident bundle; this tool
lets the RECIPIENT (regulator, supervisor, internal audit) verify a received
`dist/` tree **without trusting the packager**:

- It is deliberately standalone: Python 3 standard library only (the optional
  ML-DSA-65 signature check uses `dilithium-py` if present).
- It deliberately does NOT import the packager. The digest rules
  (byte SHA-256, timestamp-normalized content SHA-256, sorted-digest bundle
  digests) are re-implemented independently, so a bug or backdoor in the
  packager cannot vouch for itself.

What is checked (each check is named and falsifiable)
-----------------------------------------------------
1.  manifest-parse            MANIFEST.json parses and has the expected shape.
2.  artifact-presence         Every manifest artifact exists in artifacts/.
3.  artifact-byte-digest      Byte SHA-256 of each bundled file == .sha256.
4.  artifact-content-digest   Timestamp-normalized SHA-256 == .content_sha256.
5.  bundle-digest-recompute   bundle_sha256 == SHA-256(sorted byte digests).
6.  content-digest-recompute  content_digest == SHA-256(sorted content digests).
7.  digests-distinct          The two bundle-level digests differ (they must:
                              they answer different questions).
8.  summary-consistency       The manifest's claimed unit counts / coverage
                              gaps / conformance are recomputed from the
                              bundled deliverable JSONs themselves — a manifest
                              that inflates units_satisfied or hides a gap FAILS.
9.  conformance-claims        all_catalogs_conformant is true iff every bundled
                              deliverable JSON reports 0 conformance failures.
10. signature (optional)      If MANIFEST.sig.json is present, the detached
                              ML-DSA-65 signature over the exact MANIFEST.json
                              bytes verifies against the embedded public key,
                              and the key's SHA-256 fingerprint is reported so
                              it can be compared out-of-band.

Honesty notes
-------------
- A VERIFIED result proves assembly integrity and internal consistency of the
  received bundle. It is NOT a conformity assessment, certification, or safety
  proof, and it does not re-run the assurance suite (use
  EXECUTION_CHECKLIST.md for full reproduction).
- The signature proves the manifest is unaltered since signing by the holder
  of the secret key. It proves signer IDENTITY only if the reported public-key
  fingerprint is compared against a fingerprint obtained out-of-band.
- If `dilithium-py` is unavailable the signature check is reported as SKIPPED,
  never silently passed. `--require-signature` turns absence/skip into FAIL.

Usage
-----
  python3 governance_artifacts/verify_distribution_bundle.py
  python3 governance_artifacts/verify_distribution_bundle.py --bundle-dir path/to/dist
  python3 governance_artifacts/verify_distribution_bundle.py --print          # JSON report
  python3 governance_artifacts/verify_distribution_bundle.py --require-signature
Exit code 0 iff every executed check passes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Independent re-implementation of the packager's normalization rule:
# ISO-8601 UTC instants are the only sanctioned non-deterministic content.
ISO_INSTANT_RE = re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
NORMALIZED_INSTANT = b"<NORMALIZED-TIMESTAMP>"

# Deliverable JSON top-level key + unit array key, needed to recompute the
# manifest's claims from the bundled artifacts themselves.
DELIVERABLE_SHAPE = {
    "eu-ai-act-annex-iv": ("dossier", "sections"),
    "dora-ict-risk-register": ("dora_register", "pillars"),
    "nist-ai-rmf-crosswalk": ("nist_rmf_crosswalk", "functions"),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_sha256_bytes(data: bytes) -> str:
    return sha256_bytes(ISO_INSTANT_RE.sub(NORMALIZED_INSTANT, data))


def _unit_status(unit: dict) -> str:
    return unit.get("evidence_status") or unit.get("status") or "UNKNOWN"


def verify_bundle(bundle_dir: Path, require_signature: bool = False) -> dict:
    """Run every check against a received bundle directory. Returns a report."""
    checks: list[dict] = []
    errors: list[str] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "status": "PASS" if ok else "FAIL",
                       "detail": detail})
        if not ok:
            errors.append(f"{name}: {detail}")

    # -- 1. manifest-parse ---------------------------------------------------
    manifest_path = bundle_dir / "MANIFEST.json"
    if not manifest_path.exists():
        record("manifest-parse", False, f"missing {manifest_path}")
        return _report(bundle_dir, checks, errors)
    manifest_bytes = manifest_path.read_bytes()
    try:
        bundle = json.loads(manifest_bytes)["bundle"]
        artifacts = bundle["artifacts"]
        assert isinstance(artifacts, list) and artifacts
        record("manifest-parse", True,
               f"{len(artifacts)} artifacts declared, "
               f"{len(bundle.get('deliverables', []))} deliverables")
    except (KeyError, ValueError, AssertionError) as exc:
        record("manifest-parse", False, f"malformed manifest: {exc!r}")
        return _report(bundle_dir, checks, errors)

    # -- 2-4. per-artifact presence + digests -------------------------------
    present, byte_ok, content_ok = 0, 0, 0
    for art in artifacts:
        rel = art.get("bundled_as") or art.get("path", "")
        p = bundle_dir / rel
        if not p.exists():
            record("artifact-presence", False, f"missing bundled artifact: {rel}")
            continue
        present += 1
        raw = p.read_bytes()
        if sha256_bytes(raw) == art.get("sha256"):
            byte_ok += 1
        else:
            record("artifact-byte-digest", False,
                   f"byte SHA-256 mismatch (tampered or corrupted): {rel}")
        if content_sha256_bytes(raw) == art.get("content_sha256"):
            content_ok += 1
        else:
            record("artifact-content-digest", False,
                   f"content SHA-256 mismatch (content altered): {rel}")
    if present == len(artifacts):
        record("artifact-presence", True, f"all {present} bundled artifacts present")
    if byte_ok == present and present == len(artifacts):
        record("artifact-byte-digest", True,
               f"all {byte_ok} byte digests match MANIFEST.json")
    if content_ok == present and present == len(artifacts):
        record("artifact-content-digest", True,
               f"all {content_ok} timestamp-normalized digests match")

    # -- 5-7. bundle-level digests -------------------------------------------
    basis = "".join(sorted(a["sha256"] for a in artifacts)).encode()
    ok = sha256_bytes(basis) == bundle.get("bundle_sha256")
    record("bundle-digest-recompute", ok,
           "bundle_sha256 recomputes from sorted per-artifact byte digests"
           if ok else "bundle_sha256 does NOT recompute (manifest altered)")

    cbasis = "".join(sorted(a["content_sha256"] for a in artifacts)).encode()
    ok = sha256_bytes(cbasis) == bundle.get("content_digest")
    record("content-digest-recompute", ok,
           "content_digest recomputes from sorted per-artifact content digests"
           if ok else "content_digest does NOT recompute (manifest altered)")

    ok = bundle.get("bundle_sha256") != bundle.get("content_digest")
    record("digests-distinct", ok,
           "provenance and reproducibility digests are distinct" if ok
           else "bundle_sha256 == content_digest (impossible for honest bundle)")

    # -- 8-9. manifest claims vs bundled deliverable content ------------------
    recomputed_units = recomputed_satisfied = recomputed_gaps = 0
    any_conformance_failure = False
    consistency_ok = True
    for deliv in bundle.get("deliverables", []):
        shape = DELIVERABLE_SHAPE.get(deliv.get("id"))
        json_art = next(
            (a for a in artifacts
             if a.get("deliverable_id") == deliv.get("id") and a.get("kind") == "json"),
            None)
        if shape is None or json_art is None:
            consistency_ok = False
            record("summary-consistency", False,
                   f"unknown deliverable or missing JSON artifact: {deliv.get('id')}")
            continue
        rel = json_art.get("bundled_as") or json_art.get("path", "")
        p = bundle_dir / rel
        if not p.exists():
            continue  # already failed artifact-presence
        root_key, unit_key = shape
        root = json.loads(p.read_bytes())[root_key]
        units = root.get(unit_key, [])
        satisfied = sum(1 for u in units if _unit_status(u) == "SATISFIED")
        gaps = [u for u in units
                if u.get("is_coverage_gap") or _unit_status(u) == "PENDING-EVIDENCE"]
        failed = int(root.get("catalog_conformance", {}).get("failed", 0))
        any_conformance_failure |= failed != 0

        recomputed_units += len(units)
        recomputed_satisfied += satisfied
        recomputed_gaps += len(gaps)

        for claim, actual, label in (
                (deliv.get("units_total"), len(units), "units_total"),
                (deliv.get("units_satisfied"), satisfied, "units_satisfied"),
                (len(deliv.get("coverage_gaps", [])), len(gaps), "coverage_gaps"),
                (deliv.get("catalog_conformance_failed"), failed,
                 "catalog_conformance_failed")):
            if claim != actual:
                consistency_ok = False
                record("summary-consistency", False,
                       f"{deliv['id']}: manifest claims {label}={claim} but "
                       f"bundled artifact contains {actual} (manifest forged?)")

    summary = bundle.get("summary", {})
    for claim, actual, label in (
            (summary.get("units_total"), recomputed_units, "units_total"),
            (summary.get("units_satisfied"), recomputed_satisfied, "units_satisfied"),
            (summary.get("coverage_gaps"), recomputed_gaps, "coverage_gaps")):
        if claim != actual:
            consistency_ok = False
            record("summary-consistency", False,
                   f"bundle summary claims {label}={claim} but recomputation "
                   f"from bundled artifacts gives {actual}")
    if consistency_ok:
        record("summary-consistency", True,
               f"manifest claims match bundled content: "
               f"{recomputed_satisfied}/{recomputed_units} units SATISFIED, "
               f"{recomputed_gaps} declared gap(s)")

    claimed_conformant = bool(summary.get("all_catalogs_conformant"))
    ok = claimed_conformant == (not any_conformance_failure)
    record("conformance-claims", ok,
           f"all_catalogs_conformant={claimed_conformant} agrees with bundled "
           f"deliverables" if ok else
           "all_catalogs_conformant disagrees with the bundled deliverables")

    # -- 10. optional detached ML-DSA-65 signature ----------------------------
    sig_path = bundle_dir / "MANIFEST.sig.json"
    if sig_path.exists():
        try:
            sig = json.loads(sig_path.read_text())["signature"]
            pk = bytes.fromhex(sig["public_key_hex"])
            fingerprint = sha256_bytes(pk)
            if sig.get("alg") != "ML-DSA-65":
                record("signature", False,
                       f"unexpected signature alg: {sig.get('alg')!r}")
            elif fingerprint != sig.get("public_key_sha256"):
                record("signature", False,
                       "embedded public key does not match its declared fingerprint")
            else:
                try:
                    from dilithium_py.ml_dsa import ML_DSA_65
                except ImportError:
                    detail = ("MANIFEST.sig.json present but dilithium-py is not "
                              "installed; signature NOT verified")
                    if require_signature:
                        record("signature", False, detail)
                    else:
                        checks.append({"check": "signature", "status": "SKIPPED",
                                       "detail": detail})
                else:
                    valid = ML_DSA_65.verify(
                        pk, manifest_bytes, bytes.fromhex(sig["signature_hex"]))
                    record("signature", valid,
                           f"ML-DSA-65 signature over MANIFEST.json verifies; "
                           f"public-key fingerprint {fingerprint} (compare "
                           f"out-of-band)" if valid else
                           "ML-DSA-65 signature INVALID for these MANIFEST.json "
                           "bytes (manifest or signature altered)")
        except (KeyError, ValueError) as exc:
            record("signature", False, f"malformed MANIFEST.sig.json: {exc!r}")
    elif require_signature:
        record("signature", False,
               "MANIFEST.sig.json required (--require-signature) but absent")
    else:
        checks.append({"check": "signature", "status": "SKIPPED",
                       "detail": "no MANIFEST.sig.json in bundle (optional)"})

    return _report(bundle_dir, checks, errors)


def _report(bundle_dir: Path, checks: list[dict], errors: list[str]) -> dict:
    status = "VERIFIED" if not errors else "FAILED"
    return {
        "verification": {
            "bundle_dir": str(bundle_dir),
            "verifier": "governance_artifacts/verify_distribution_bundle.py",
            "status": status,
            "checks": checks,
            "errors": errors,
            "integrity_statement": (
                "A VERIFIED result proves assembly integrity and internal "
                "consistency of the received bundle, independently of the "
                "packager. It is NOT a conformity assessment, certification, "
                "or safety proof; full reproduction is described in "
                "EXECUTION_CHECKLIST.md."),
        }
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ga_dir = Path(__file__).resolve().parent
    ap.add_argument("--bundle-dir", default=str(ga_dir / "dist"),
                    help="received bundle directory (default: governance_artifacts/dist)")
    ap.add_argument("--require-signature", action="store_true",
                    help="fail unless a valid ML-DSA-65 MANIFEST.sig.json is present")
    ap.add_argument("--print", dest="print_json", action="store_true",
                    help="print the full JSON verification report")
    args = ap.parse_args()

    report = verify_bundle(Path(args.bundle_dir),
                           require_signature=args.require_signature)
    v = report["verification"]

    if args.print_json:
        print(json.dumps(report, indent=2))
    else:
        for c in v["checks"]:
            print(f"  [{c['status']:>7}] {c['check']}: {c['detail']}")
        print(f"Bundle verification: {v['status']} "
              f"({sum(1 for c in v['checks'] if c['status'] == 'PASS')} checks PASS, "
              f"{len(v['errors'])} error(s))")
    return 0 if v["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(main())
