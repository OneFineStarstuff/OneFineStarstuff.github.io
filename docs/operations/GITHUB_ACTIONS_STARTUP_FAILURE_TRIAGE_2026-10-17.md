<title>GitHub Actions Startup-Failure Triage — 17 October 2026</title>

<abstract>
Incident note for repository `OneFineStarstuff/OneFineStarstuff.github.io`. Several Actions executions terminate almost immediately with `startup_failure`, no job records, and no step logs. This note separates verified observations from hypotheses, records the workflow-definition corrections already made in draft PR #166, and provides a support-ready diagnostic packet. The exact cause is **unconfirmed**.
</abstract>

<content>

## 1. Executive assessment

**Disposition: CI DISPATCH / STARTUP FAILURE — INVESTIGATION REQUIRED.**

The observed Python CI and Governance Docs Lint runs fail before any step-level logs or jobs are exposed by the Actions API. Consequently, these events cannot be diagnosed as Python dependency failures, pytest failures, ShellCheck findings, or Markdown lint findings. A failure before job creation is different from a workflow job that starts and fails during its steps.

The run metadata inspected so far identifies the expected registered workflow IDs and paths, rather than the synthetic `path: BuildFailed` / empty-name signature reported in some public community discussions. This is an important distinction: the evidence does **not** establish that this repository has the same orphaned-workflow-registry fault. It does establish that repeatedly changing application code or rerunning the two workflows without new diagnostic evidence is unlikely to explain a failure where no steps execute.

## 2. Verified observations

Observed on head commit `dc889bfda892931c5c5f753223c24df18747b25f` at approximately 2026-10-16 15:35 UTC:

| Workflow | Run | Workflow ID | Recorded path | Event | Result |
|---|---:|---:|---|---|---|
| Python CI | [38925139796](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/38925139796) | `326080002` | `.github/workflows/ci.yml` | `pull_request` | `startup_failure`; job list empty |
| Governance Docs Lint | [38925141592](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/38925141592) | `286785951` | `.github/workflows/governance-docs-lint.yml` | `pull_request` | `startup_failure`; job list empty |

The same workflow IDs and paths were reported for earlier main-branch runs:

- [Python CI run 38923391324](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/38923391324)
- [Governance Docs Lint run 38923392683](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/38923392683)

For these inspected runs, the Actions jobs endpoint returned no jobs; step logs therefore could not be obtained. The recorded run path and workflow ID fields were populated with the named workflows. This report does not infer an unobserved backend mechanism from those facts.

The same no-job signature recurred on PR head `4aac7a083aa29965614c9936eebbc3149951843f` on 17 October 2026 at 04:36 UTC:
- [Python CI run 39003216023](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/39003216023) — workflow ID `326080002`, recorded path `.github/workflows/ci.yml`, conclusion `startup_failure`, job list empty.
- [Governance Docs Lint run 39003216586](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/actions/runs/39003216586) — workflow ID `286785951`, recorded path `.github/workflows/governance-docs-lint.yml`, conclusion `startup_failure`, job list empty.

On the same head, **Governance Artifact Validation** and **Makefile CI** both completed successfully. This shows that not every workflow was blocked on that commit, but it does not explain why these two specific workflow executions failed before exposing jobs.

## 3. Workflow-definition repairs already included in draft PR #166

Draft PR: [#166 — fix(ci,docs): repair workflows and qualify GIEN evidence](https://github.com/OneFineStarstuff/OneFineStarstuff.github.io/pull/166).

The following separate, concrete workflow-file defects were corrected on the PR branch:

- `jekyll-docker.yml`: shell block indentation. Its build job subsequently completed successfully on a preceding PR commit.
- `nextjs.yml`: GitHub Pages `deploy.environment` mapping indentation.
- `manual.yml`: `workflow_dispatch.inputs.name` nesting.
- `webpack.yml`: previous sample expected a root-level Webpack project that is not present; replaced with a scoped Next.js frontend workflow targeting `next-app`.
- `sentinel-governance-gates.yml`: `if-no-files-found` moved inside the upload-artifact action's `with` inputs.

Those fixes address identified workflow configuration problems. They do not, by themselves, explain the two remaining no-job `startup_failure` runs.

## 4. Evidence-based interpretation

The current evidence supports these statements:

1. The workflow executions named above failed before any accessible job steps were recorded.
2. The returned run metadata maps to the expected workflow IDs and file paths.
3. Earlier unrelated failures were traced to actual malformed workflow definitions and corrected in the draft PR.
4. The remaining Python CI and Governance Docs Lint failures do not expose step-level evidence from which a test or script failure can be diagnosed.
5. GitHub community reports from August–September 2026 describe other cases of `startup_failure` with zero jobs. Some report a synthetic `BuildFailed` path, while another reports failure even when a `workflow_dispatch` run was attached to a correctly registered workflow. These are user-reported incidents, not an official root-cause analysis or confirmation that this repository shares a particular backend defect:
   - [GitHub Community discussion #206103](https://github.com/orgs/community/discussions/206103)
   - [GitHub Community discussion #208287](https://github.com/orgs/community/discussions/208287)

Do not claim an incident is caused by a ghost workflow registry row unless the workflow metadata confirms that signature or GitHub Support verifies it.

## 5. Recommended diagnostics

Collect the following from an authenticated repository or organization administrator session:

1. Open the two failed run pages and capture the complete displayed message, run metadata, and timestamps.
2. Query the Actions API for each run's job list. Preserve the response and confirm whether the array is empty. If no job exists, there cannot be a step log for that run.
3. List registered workflows and record the workflow IDs, paths, names, state, and most recent successful run for each. Compare the recorded IDs/paths with those in Section 2.
4. Confirm that GitHub Actions is enabled for the repository, the relevant workflows are active, the applicable actions policy permits required actions, and no repository/account policy or usage limit blocks runners.
5. Validate the two workflow files in a local workflow linter or trusted CI replica, while recognizing that successful YAML lint does not establish that GitHub's event dispatcher started a job.
6. Avoid repeated reruns and additional workflow renames until one of these observations changes. Repeated identical no-job failures add little diagnostic information.

## 6. Support-ready incident packet

Use this summary if escalating to GitHub Support:

> **Subject:** Repeated GitHub Actions `startup_failure` before job creation — Python CI and Governance Docs Lint
>
> Repository: `OneFineStarstuff/OneFineStarstuff.github.io`
>
> Affected run IDs: `38925139796`, `38925141592`, `38923391324`, `38923392683`
>
> Workflow IDs and paths: `326080002 / .github/workflows/ci.yml`; `286785951 / .github/workflows/governance-docs-lint.yml`
>
> Observed behavior: run concludes `startup_failure` immediately; Actions jobs API returns an empty job list; no step-level logs are available. The API records the expected workflow paths and IDs in these examples. This differs from the commonly reported `path: BuildFailed` / empty workflow-name pattern, so the underlying cause is not assumed.
>
> Remediation already attempted: reviewed workflow YAML, corrected unrelated concrete defects in draft PR #166, and confirmed those fixes do not resolve these two no-job runs.
>
> Request: investigate why these registered workflow executions fail before a job graph or runner job is exposed; provide any available platform-side failure reason or recommended administrator action.

Do not include credentials, secrets, access tokens, or personal data in a support packet. Keep the PR in draft until the required checks have a verifiable disposition.

## 7. Exit criteria

Close the incident only when either:

- a new run produces jobs and a test/build result that can be diagnosed and validated, or
- GitHub Support provides an actionable cause and the remediation is confirmed by a subsequent run.

A queued, skipped, successful unrelated workflow, or passing code-quality integration does not close this incident.


</content>
