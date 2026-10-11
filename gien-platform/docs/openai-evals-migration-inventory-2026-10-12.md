# OpenAI Evals Migration Inventory and Cutover Plan

**Inventory date:** 12 October 2026  
**Owner:** UNASSIGNED — platform/AI quality owner must be named  
**Inventory state:** NOT INVENTORIED  
**GIEN scope:** research-evaluation assets, source-to-claim regression corpus, prompts and graders used by the prototype or a future service.

> **Boundary:** The repository connection does not expose the user's OpenAI organization, Evals workspace, dashboard content, or API inventory. This document is a controlled inventory template, not a finding that any particular Evals assets exist or have been exported.

## 1. Confirmed timeline and immediate priority

OpenAI's official [API deprecations notice](https://developers.openai.com/api/docs/deprecations) states that existing Evals become read-only on **31 October 2026** and that the Evals dashboard and API are scheduled to shut down on **30 November 2026**. The Evals documentation also says graders documented for eval workflows are part of the transition. The dates below are published vendor dates, not GIEN-created targets.

| Date (UTC) | Vendor milestone | Required GIEN action |
|---|---|---|
| 12–16 Oct 2026 | Pre-cutover inventory | Name owner and backup; enumerate workspaces, projects, eval definitions, item data, graders, runs, prompts, API/CI references and retention requirements. |
| 17–21 Oct 2026 | Export and preserve | Export available definitions, test inputs/expected outputs, graders/rubrics, results, traces and referenced media; redact secrets; verify each export opens and is complete. |
| 22–27 Oct 2026 | Successor proof of concept | Evaluate Promptfoo as the documented migration path; separately assess OpenAI Datasets for the workflows it supports. Record feature gaps, data handling, repeatability, access control and CI integration. |
| 28–30 Oct 2026 | Read-only freeze readiness | Reconcile object counts, sample-check records and results, compute file hashes, retain export manifest and owner sign-off. Do not defer final exports until the read-only transition. |
| 31 Oct 2026 | Evals becomes read-only | Treat legacy Evals assets as non-editable and use verified exports for ongoing migration work. |
| 1–29 Nov 2026 | Migration verification | Import representative eval exports, compare test case and result fidelity, rerun the regression corpus, record differences and obtain approval for the replacement workflow. |
| 30 Nov 2026 | Dashboard/API scheduled shutdown | Remove active dependency on the retired platform after the replacement is approved; retain approved audit exports and migration evidence under the applicable retention policy. |

**Immediate risk:** As of 12 October, 19 calendar days remain until the read-only milestone and 49 calendar days remain until the scheduled shutdown. Confirm dates on the official deprecations page before executing the cutover.

## 2. Inventory status register

Set each row to NOT_PRESENT only after a responsible owner has searched all in-scope workspaces, repositories, CI configurations and secrets references. A blank, missing or inaccessible inventory is NOT INVENTORIED—not evidence that no assets exist.

| Asset category | Required inventory fields | Current status | Owner / evidence |
|---|---|---|---|
| OpenAI organizations and projects | Organization/project identifiers, administrators, applicable workspace(s), data classification | NOT INVENTORIED | Owner: ___ · Search evidence: ___ |
| Evals definitions | Eval ID/name, schema/version, creation/update date, input/output contract, source project | NOT INVENTORIED | Owner: ___ · Export URI: ___ |
| Eval items / datasets | Item IDs/count, JSONL/CSV exports, expected outputs, labels, metadata, references to files | NOT INVENTORIED | Owner: ___ · Count/hash: ___ |
| Graders and rubrics | Grader ID/version/type, prompt/rubric, thresholds, dependencies, test fixtures | NOT INVENTORIED | Owner: ___ · Export URI: ___ |
| Eval runs and results | Run IDs/count, timestamps, model IDs, statuses, scores, sampled outputs, error records | NOT INVENTORIED | Owner: ___ · Count/hash: ___ |
| Prompts / reusable prompt objects | Prompt IDs/versions, template variables, system instructions, linked evals, API/CI consumers | NOT INVENTORIED | Owner: ___ · Migration commit: ___ |
| Traces and attached media | Trace references, artifact type, size, retention/access constraints, media inclusion | NOT INVENTORIED | Owner: ___ · Export verification: ___ |
| Automation dependencies | Repository paths, workflow names, cron/scheduled jobs, service accounts, endpoint calls, alerts | NOT INVENTORIED | Owner: ___ · Removal PR: ___ |
| Access and secret boundary | Owners/reviewers, service credentials, secret references (never secret values), least-privilege review | NOT INVENTORIED | Owner: ___ · Review record: ___ |
| Retention and compliance | Legal hold, retention class, personal/confidential data, redaction rules, deletion approval | NOT INVENTORIED | Owner: ___ · Policy reference: ___ |

### Per-asset export manifest template

For each asset or export package, record:

- inventory item ID, asset category, source platform, source object ID, owner and backup owner;
- export timestamp in UTC, exporter/version, original object count and exported count;
- filenames, byte sizes, SHA-256 digests, data classification and redaction result;
- referenced blobs/media included or intentionally omitted, with reason;
- import target/tool/version, import result, parity-test ID, differences, reviewer and disposition;
- backup location, access policy, retention date and restore-test evidence.

Keep raw exports immutable where policy requires it. Store credentials only in an approved secret manager; strip secret values and sensitive personal data from migration logs. A digest proves byte consistency, not content correctness or completeness.

## 3. Successor selection and parity test

OpenAI's [deprecation notice links to a migration path from OpenAI Evals to Promptfoo](https://www.promptfoo.dev/docs/usage/command-line/). Promptfoo documents an import workflow for OpenAI Evals dashboard JSONL exports, including preservation of available configuration, results, prompts, variables, runtime options and durations. It also documents limitations: relationships such as local tags, dataset links, cache entries and sharing state are not reconstructed. Confirm the current CLI format and capability before importing production assets.

Do not assume that format parity implies semantic parity. Test a representative export containing every grader type used by the team, edge-case outputs, failures/timeouts and linked files/media. Preserve original Evals exports so a migration discrepancy can be investigated without relying on the destination alone.

### Required acceptance checks

1. Exported item counts reconcile to the source inventory; missing/unreadable objects are identified.
2. Every exported file can be parsed; JSONL line counts and schema validity are recorded.
3. Prompts, model identifiers, tool setup, rubrics, grader configuration, thresholds and expected outputs are version-controlled.
4. Secrets are redacted from exported config and logs; sensitive traces have approved access and retention.
5. A stable subset of test items produces comparable, explainable results on the successor; grader changes are reported separately from model-output changes.
6. Citation validation tests include unsupported claims, citation mismatch, contradictory sources, stale evidence, malformed URL, missing source, reviewer omission and duplicate IDs.
7. Results retain run timestamp, code/config revision, provider/model, tool configuration, test-case IDs, grader version, duration, failures, and export digests.
8. The migration has an owner, rollback decision, approved cutover, and documented residual gaps.
9. CI runs a deterministic no-network regression corpus for the structural claim-evidence rules; model-graded tests are separate and explicitly nondeterministic.
10. A successful evaluation run cannot automatically approve a governance control, authorize a deployment, or mark regulatory compliance as established.

## 4. Current GIEN implementation checkpoint

| Work item | Initial status |
|---|---|
| Live OpenAI Evals asset scan | NOT AVAILABLE from this repository connector; owner action required |
| Export inventory and manifest | TEMPLATE CREATED; no exports supplied or verified |
| Claim-to-source structure validation | IMPLEMENTED IN PROTOTYPE; structural only |
| Deterministic regression suite | IMPLEMENTED; execution must be confirmed by CI |
| Source semantic entailment / source reachability | NOT AUTOMATED |
| Human approval, backend persistence, access control | NOT IMPLEMENTED in this prototype |
| Promptfoo/alternative parity test | NOT RUN; requires representative authorized exports |
| Production migration or assurance | NOT ASSERTED |

## 5. Authoritative references (reviewed 12 October 2026)

- OpenAI API deprecations and Evals timeline: https://developers.openai.com/api/docs/deprecations
- OpenAI Evals guide: https://developers.openai.com/api/docs/guides/evals
- OpenAI evaluation best practices: https://developers.openai.com/api/docs/guides/evaluation-best-practices
- OpenAI datasets guide: https://developers.openai.com/api/docs/guides/evaluation-getting-started
- Promptfoo CLI export/import reference: https://www.promptfoo.dev/docs/usage/command-line/

Re-check vendor dates, current migration documentation, CLI version and feature parity before cutover. This inventory is a work plan and evidence template, not a statement that any service account, export, or production evaluation workflow has been inspected.
