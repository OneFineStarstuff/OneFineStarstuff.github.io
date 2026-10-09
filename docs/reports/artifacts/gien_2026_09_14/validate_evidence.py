#!/usr/bin/env python3
"""Read-only validation of this evidence package; never a compliance certificate.

Requires Python 3.10+, jsonschema and regex. Does not fetch URLs, execute the
assurance suite, resolve the missing assessment plan, or verify production data.
An exit code of zero means only the explicitly reported local checks passed.
The manifest is unsigned: compare it against an independently trusted copy.
"""
import sys

sys.dont_write_bytecode = True

import copy
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import regex
from jsonschema import Draft7Validator, FormatChecker, ValidationError, validators

HERE = Path(__file__).resolve().parent
REPORTS = HERE.parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def within(base, relative):
    require(isinstance(relative, str), "Path must be a string")
    path = (base / relative).resolve()
    require(path.is_relative_to(base.resolve()), "Path escapes package boundary")
    require(path.is_file(), "Missing file: " + relative)
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instant(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(dt.tzinfo is not None, "Timezone missing")
    return dt


def ids(node):
    found = set()
    if isinstance(node, dict):
        found.update(c["id"] for c in node.get("controls", []))
        for value in node.values():
            found.update(ids(value))
    elif isinstance(node, list):
        for value in node:
            found.update(ids(value))
    return found


def unicode_pattern(validator, pattern, instance, schema):
    if isinstance(instance, str) and regex.search(pattern, instance) is None:
        yield ValidationError(repr(instance) + " does not match " + repr(pattern))


def validate():
    manifest = load(HERE / "evidence_manifest.json")
    paths = [a["path"] for a in manifest["artifacts"]]
    require(len(paths) == len(set(paths)), "Duplicate manifest paths")
    for artifact in manifest["artifacts"]:
        path = within(REPORTS, artifact["path"])
        require(path.stat().st_size == artifact["bytes"], "Byte count mismatch")
        require(digest(path) == artifact["sha256"], "Digest mismatch: " + artifact["path"])
    expected = {within(REPORTS, p) for p in paths}
    actual = {p.resolve() for p in HERE.iterdir() if p.is_file() and p.name != "evidence_manifest.json"}
    actual.add(within(REPORTS, manifest["report_path"]))
    require(expected == actual, "Manifest inventory differs from package files")

    text = within(REPORTS, manifest["report_path"]).read_text(encoding="utf-8")
    doc = manifest["document_id"]
    anchors = manifest["specification_anchors"]
    for tag, value in anchors.items():
        require(hashlib.sha256((doc + "/" + tag).encode()).hexdigest() == value,
                "Incorrect specification identifier: " + tag)
    prior = set(manifest["predecessor"]["specification_labels"].values())
    hashes = re.findall(r"0x([0-9a-fA-F]+)", text)
    checks = {
        "hash_count": len(hashes) == 39,
        "hash_lengths": all(len(h) == 64 for h in hashes),
        "current_anchors": len(anchors) == 37 and set(anchors.values()) <= set(hashes),
        "no_unknown_hashes": set(hashes) == set(anchors.values()) | prior,
        "predecessor_labels": len(prior) == 2 and prior <= set(hashes),
        "predecessor_reference": manifest["predecessor"]["document_id"] in text,
        "no_placeholders": re.search(r"@A\(|CONTINUATION-SENTINEL|SECOND-HALF|TODO|TBD|FIXME|<placeholder", text) is None,
        "balanced_tags": all(text.count("<" + tag + ">") == text.count("</" + tag + ">") == 1
                             for tag in ("title", "abstract", "content")),
        "ten_sections": len(re.findall(r"^# SECTION ", text, re.M)) == 10,
        "document_id": doc in text,
        "evidence_tiers": all(tier in text for tier in ("Tier A", "Tier B/C", "Tier D")),
        "anchor_recipe": 'sha256("' + doc + '/" + TAG)' in text,
    }
    require(all(checks.values()), "Document checks failed: " + repr(checks))

    schema_path = HERE / "oscal_assessment-results_schema_1.1.2.json"
    require(digest(schema_path) == manifest["schema_source"]["sha256"], "Schema digest mismatch")
    schema = load(schema_path)
    checker = FormatChecker()

    @checker.checks("regex", raises=regex.error)
    def valid_regex(value):
        return not isinstance(value, str) or regex.compile(value) is not None

    Draft7Validator.check_schema(schema, format_checker=checker)
    engine = validators.extend(Draft7Validator, {"pattern": unicode_pattern})
    validator = engine(schema, format_checker=checker)
    assessment = load(HERE / "assessment-results.json")
    validator.validate(assessment)
    for mutation in ("bad_token", "bad_timestamp", "missing_required_field"):
        bad = copy.deepcopy(assessment)
        result = bad["assessment-results"]["results"][0]
        if mutation == "bad_token":
            result["reviewed-controls"]["control-selections"][0]["include-controls"][0]["control-id"] = "bad space"
        elif mutation == "bad_timestamp":
            result["observations"][0]["collected"] = "yesterday"
        else:
            del bad["assessment-results"]["metadata"]
        require(bool(list(validator.iter_errors(bad))), "Mutation unexpectedly accepted: " + mutation)

    catalog_ids = set()
    for name in ("catalog_sentinel_v24_excerpt.json", "catalog_sentinel_v24_env_rte.json"):
        catalog_ids.update(ids(load(HERE / name)))
    result = assessment["assessment-results"]["results"][0]
    selected = {item["control-id"] for selection in result["reviewed-controls"]["control-selections"]
                for item in selection["include-controls"]}
    ledger = load(HERE / "evidence_freshness_ledger.json")["evidence_freshness_ledger"]
    entries = {item["control_id"]: item for item in ledger["entries"]}
    require(len(entries) == len(ledger["entries"]) == 7, "Invalid ledger population")
    require(selected == set(entries) and selected <= catalog_ids, "Control references do not resolve")
    require(sum(e["passed"] is True for e in entries.values()) == 6, "Expected six local passes")
    require(entries["env-02"]["passed"] is None, "Hardware gap incorrectly marked passed")
    encoded = json.dumps(ledger["entries"], sort_keys=True, separators=(",", ":")).encode()
    require(hashlib.sha256(encoded).hexdigest() == ledger["ledger_sha256"], "Ledger digest mismatch")
    run = manifest["test_run"]
    require(result["start"] == run["start"] and result["end"] == run["end"], "Run timestamp mismatch")
    require(instant(manifest["reporting_window"]["end_exclusive"]) <= instant(run["start"]),
            "Expected post-window verification")
    require(instant(run["start"]) <= instant(run["end"]), "Reversed run interval")
    observed = set()
    for observation in result["observations"]:
        props = {p["name"]: p["value"] for p in observation["props"]}
        cid = props["control-id"]
        require(cid in entries and cid not in observed, "Invalid or duplicated observation")
        observed.add(cid)
        expected_result = "PASS-LOCAL-CHECK" if entries[cid]["passed"] is True else "NOT-RUNNABLE-EVIDENCE-MISSING"
        require(props["result"] == expected_result, "Observation inflates evidence")
        require(observation["collected"] == (entries[cid]["evidence_generated_at"] or run["end"]),
                "Observation collection time differs from ledger")
        require(instant(run["start"]) <= instant(observation["collected"]) <= instant(run["end"]),
                "Collection outside run interval")
        for evidence in observation["relevant-evidence"]:
            within(HERE, evidence["href"])
    require(observed == selected, "Observation population mismatch")
    require("UNRESOLVED" in assessment["assessment-results"]["import-ap"]["remarks"],
            "Missing-plan limitation not disclosed")

    log = re.sub(r"\x1b\[[0-9;]*m", "", (HERE / "assurance.log").read_text())
    require(len(re.findall(r"^  PASS  ", log, re.M)) == 19, "Suite pass count mismatch")
    require({int(n) for n in re.findall(r"^\[(\d+)/19\]", log, re.M)} == set(range(1, 20)),
            "Suite steps missing")
    snapshot = load(HERE / "operational_snapshot.json")
    require(snapshot["document_id"] == doc and snapshot["reporting_window"] == manifest["reporting_window"],
            "Operational snapshot scope mismatch")
    require(all(m["value"] is None and m["observed_at"] is None and m["status"] == "NOT-OBSERVED"
                for m in snapshot["metrics"].values()), "Unsupported current telemetry")
    require(len(snapshot["domains"]) == 10 and all(d["operational_verification"] is None
                                                  for d in snapshot["domains"]), "Domain claim inflated")
    return {
        "status": "PASS-SCOPED-PACKAGE-CHECKS",
        "document_consistency": {"passed": 12, "total": 12, "checks": checks},
        "artifact_digests_and_inventory": "PASS",
        "oscal_1_1_2_schema_and_formats": "PASS",
        "negative_schema_tests": {"invalid_token": "REJECTED", "invalid_datetime": "REJECTED",
                                  "missing_required_field": "REJECTED"},
        "local_control_references_and_collection_times": "PASS",
        "suite_log_steps": 19,
        "unsupported_current_telemetry": "NONE_ASSERTED",
        "assessment_plan_import": "UNRESOLVED-NOT-VALIDATED",
        "source_repository_files": "NOT-CHECKED-BY-PORTABLE-VERIFIER",
        "production_and_legal_conformity": "NOT-ASSESSED",
        "notice": "Unsigned manifest; schema-valid draft is not a complete OSCAL filing. Historical test evidence is not permanently fresh.",
    }


if __name__ == "__main__":
    try:
        print(json.dumps(validate(), indent=2))
    except (OSError, ValueError, KeyError, TypeError, ValidationError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}), file=sys.stderr)
        sys.exit(1)
