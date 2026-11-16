#!/usr/bin/env python3
"""GIEN G-SRI systemic-risk index monitor (WP-108).

Consumes the shared band thresholds (webapp/src/data/bands.json, one typed
source shared with the webapp band module), evaluates index readings, and
reports band transitions and alert-level events as structured JSON.

Fictional governance simulation: all indices are simulated data.

Usage:
    python3 gsri_monitor.py --bands webapp/src/data/bands.json \
        --reading g_sri=26.0 --reading s_sys=0.177 [--dry-run]

Exit codes: 0 = all GREEN, 1 = at least one AMBER, 2 = at least one RED,
3 = configuration/usage error.
"""

import argparse
import json
import sys
from datetime import datetime, timezone


def load_bands(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def compute_band(spec, value):
    """Band computation mirroring webapp/src/lib/bands.ts."""
    if "greenBelow" in spec:
        if value < spec["greenBelow"]:
            return "GREEN"
        return "AMBER" if value < spec["amberBelow"] else "RED"
    if "greenAbove" in spec:
        if value > spec["greenAbove"]:
            return "GREEN"
        return "AMBER" if value >= spec["amberAbove"] else "RED"
    if "greenAbs" in spec:
        a = abs(value)
        if a <= spec["greenAbs"]:
            return "GREEN"
        return "AMBER" if a <= spec["amberAbs"] else "RED"
    raise KeyError("threshold spec has no recognised shape")


def main():
    parser = argparse.ArgumentParser(description="GIEN G-SRI band monitor")
    parser.add_argument("--bands", required=True, help="path to bands.json")
    parser.add_argument("--reading", action="append", default=[],
                        help="index=value, e.g. g_sri=26.0 (repeatable)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    try:
        bands = load_bands(args.bands)
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"level": "ERROR", "event": "bands_load_failed", "error": str(exc)}))
        return 3

    specs = {}
    for group in ("lowerIsBetter", "higherIsBetter", "symmetric"):
        specs.update(bands.get(group, {}))

    readings = []
    worst = 0
    for item in args.reading:
        key, _, raw = item.partition("=")
        try:
            value = float(raw)
        except ValueError:
            print(json.dumps({"level": "ERROR", "event": "bad_reading", "reading": item}))
            return 3
        if key not in specs:
            print(json.dumps({"level": "ERROR", "event": "unknown_index", "index": key}))
            return 3
        band = compute_band(specs[key], value)
        readings.append({"index": key, "value": value, "band": band})
        worst = max(worst, {"GREEN": 0, "AMBER": 1, "RED": 2}[band])

    report = {
        "level": ("GREEN", "AMBER", "RED")[worst],
        "event": "gsri_band_report",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dry_run": args.dry_run,
        "readings": readings,
        "alert_level": "EL-%d" % (worst + 1),
    }
    print(json.dumps(report, indent=2))
    return worst


if __name__ == "__main__":
    sys.exit(main())
