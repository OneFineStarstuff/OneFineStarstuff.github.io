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

OpenAI's [deprecation notice links to a migration path from OpenAI Evals to Promptfoo](https://developers.openai.com/cookbook/examples/evaluation/moving-from-openai-evals-to-promptfoo). Distinguish two different migration paths:

- **Recreate runnable evaluations:** OpenAI's cookbook recommends manually mapping prompts, providers/models, test cases and assertions into a version-controlled `promptfooconfig.yaml`. Recreate graders as assertions/metrics, then validate the configuration and compare the new run before relying on it. The new run is separate from historical OpenAI Evals results.
- **Import historical results:** Promptfoo supports importing OpenAI Evals dashboard exports named like `eval_items_*.jsonl`. This preserves available source item/output-result metadata as historical records. The JSONL does **not** contain the full eval definition, data-source configuration, run configuration, or testing-criteria definitions. This import does **not** infer Promptfoo assertions or recreate an executable Promptfoo test configuration. Confirm current CLI format and import behavior before importing production exports.

Do not assume format parity implies semantic parity. Test a representative export containing every grader type used by the team, edge-case outputs, failures/timeouts and linked files/media. Record separately (a) historical-result import fidelity and (b) recreated-runner fidelity. Preserve original Evals exports so a migration discrepancy can be investigated without relying on the destination alone.

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

### 4.1 Repository-side scan and check triage — 12 October 2026

This scan covers the accessible repository files and CI outputs. It is not an inspection of a private OpenAI organization or an exhaustive proof that no references exist in every branch.

| Check | Finding | Disposition |
|---|---|---|
| `gien-platform/package.json` | The prototype has React/Vite dependencies and a local `test:evidence` script; no OpenAI SDK or Promptfoo dependency is declared. | NO PLATFORM RUNTIME DEPENDENCY OBSERVED in this manifest; verify external automation and user workspaces separately. |
| `.github/workflows/gien-platform-ci.yml` | CI runs npm install, deterministic evidence tests, the production build and preview smoke test. No OpenAI Evals endpoint is invoked by this workflow. | Repository prototype is not presently shown to depend on live OpenAI Evals in this workflow. |
| GitHub code search for `/v1/evals` | No matches returned. The connector's code-search operation searches the default branch, so this is a narrow corroborating result, not a complete scan of the feature branch or external scripts. | SEARCH RESULT ONLY, not proof of absence. |
| GIEN platform CI on code-bearing commit `b1cf2a89cdb20fe118c171331a4463edcdfeaabc` | The job completed successfully. Logs show 14 tests passed, 0 failed; TypeScript/Vite production build completed; seven SPA routes passed smoke testing. | PASS FOR THAT COMMIT only; a later lint issue was subsequently identified. |
| Deno workflow on merge commit `24d091ac89b66b72841ff94c75fa9446e0fde252` | `deno lint` flagged `window.setTimeout` in the new evidence page under `no-window` and `no-window-prefix`. | FIX COMMITTED: replaced with `globalThis.setTimeout` in commit `c4c1297a033e130d0cb2ec2a4fd641b32e3f1ebb`. The post-fix Deno run still needs to be observed. |
| pre-commit.ci on an earlier PR revision | The status was `failure`; the linked results page was not readable through the available repository/web connection, so individual hook output could not be inspected. | CAUSE NOT DIAGNOSED. Do not claim resolved. Inspect the run details in GitHub's PR Checks page or run `pre-commit run --all-files` locally, then commit only justified fixes. |
| Latest PR revision during this scan | PR remains open and unmerged. The lint fix had not yet produced a fresh complete result set at the time of the status query. | Inspect new Deno, GIEN CI, pre-commit.ci and other required checks before declaring the branch clean. |

#### Repository-owner actions still required

1. Open the OpenAI Platform organization and enumerate Evals objects, datasets, grader definitions, runs, prompts, traces, media and scheduled integrations; assign an owner and backup.
2. Export applicable assets before 31 October 2026, reconcile source/export counts, verify each file parses, and produce a manifest with size and SHA-256 digest. A digest alone does not prove completeness.
3. If no Evals assets or dependencies are found, record who searched, the workspace/project scope, time, and evidence used to support a `NOT_PRESENT` decision. Until then, retain `NOT_INVENTORIED`.
4. Diagnose the pre-commit.ci failure from its actual hook output; it cannot be reliably inferred from the status badge alone.
5. Re-check the feature branch's newest commit status and workflow logs after the lint fix. A previous successful build does not establish that a later commit passed.
## 5. Authoritative references (reviewed 12 October 2026)

- OpenAI API deprecations and Evals timeline: https://developers.openai.com/api/docs/deprecations
- OpenAI Evals guide: https://developers.openai.com/api/docs/guides/evals
- OpenAI evaluation best practices: https://developers.openai.com/api/docs/guides/evaluation-best-practices
- OpenAI datasets guide: https://developers.openai.com/api/docs/guides/evaluation-getting-started
- OpenAI's Evals-to-Promptfoo migration cookbook: https://developers.openai.com/cookbook/examples/evaluation/moving-from-openai-evals-to-promptfoo/
- Promptfoo CLI export/import reference: https://www.promptfoo.dev/docs/usage/command-line/ (for historical dashboard JSONL import, not full runnable-config reconstruction).

Re-check vendor dates, current migration documentation, CLI version and feature parity before cutover. This inventory is a work plan and evidence template, not a statement that any service account, export, or production evaluation workflow has been inspected.
