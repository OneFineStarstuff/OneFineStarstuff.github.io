# GitHub Integration Research for GIEN Governance Platform

**Research date:** 12 October 2026
**Repository:** OneFineStarstuff/OneFineStarstuff.GitHub.io
**Branch:** feat/gien-governance-platform
**Scope:** GitHub as source control, review, CI/CD, security evidence and controlled automation.

## 1. Executive recommendation

Treat GitHub as the versioned source of truth for GIEN application code, policy-as-code, schema definitions, CI results, change approvals and release provenance. Treat GitHub as a workflow/evidence source, not as a substitute for authoritative runtime telemetry or a cryptographic trust root.

Recommended baseline:
- Use a GitHub App for durable automation where practical, with only the repository permissions and webhook subscriptions required by the adapter. Prefer short-lived installation tokens to long-lived personal access tokens.
- Keep reads read-only. Separate PR/issue creation from code pushes, branch-protection changes, workflow edits, releases and deployments.
- Require pull-request review and relevant status checks for the protected branch; restrict bypass paths and audit them.
- In Actions, set explicit least-privilege permissions, pin third-party actions to full commit SHAs, avoid passing secrets to jobs that execute untrusted PR code, and separate build/test from deployment credentials.
- Use GitHub Actions OIDC/workload identity federation to cloud providers where supported, with exact repository, branch/environment and workflow trust conditions rather than long-lived cloud keys.
- Generate evidence from actual CI outputs and immutable commit/run identifiers. Do not infer passed from a workflow file existing or a PR being open.

## 2. Existing repository state checked

- PR #153: <https://GitHub.com/OneFineStarstuff/OneFineStarstuff.GitHub.io/pull/153>
- Branch: feat/gien-governance-platform
- Latest head at inspection: 20a2066c802762be0533d3368547b916ea2a66d0
- State: open, not merged.
- The GIEN README already links to the broader October 2026 multi-platform research report. Existing documentation identifies demo data and simulated archive/transmission controls as non-operational.
- This report is an additional focused integration plan. It does not change runtime behaviour or enable permissions.

## 3. Recommended integration architecture

Implement a typed server-side GitHub adapter behind the GIEN Integration Gateway/BFF. Never place GitHub App private keys, installation tokens, OAuth client secrets, fine-grained PATs or webhook secrets in React code, Vite-exposed environment variables, prompts, generated artifacts, client logs or browser storage.

### Read-only baseline
- Read repository metadata, approved file contents, PR metadata and review summaries.
- Read commit status/check runs and workflow-run summaries.
- Read issues only for allowlisted repositories/projects.
- Resolve source evidence to repository, commit SHA, path, line range, workflow run ID and retrieval timestamp.

### Separately authorized write capabilities
- Create an issue or PR draft in an allowlisted repository.
- Add a label or comment only after validating the caller, target, payload and duplicate/idempotency key.
- Request a review or update a branch only through a reviewed workflow.
- Trigger a deployment, publish a release, merge a PR, edit workflow files, change repository permissions, or change branch/ruleset protections only through a separate high-impact authorization path. Prefer human-operated repository administration for policy changes.

 A model may propose an operation, but it cannot grant itself a scope. The server must resolve repository/branch/PR IDs against an allowlist, check the authenticated principal and current GitHub permissions, validate schema and diff, and record the approval and resulting GitHub identifiers. Do not expose arbitrary REST/GraphQL routes or
unrestricted shell/gh execution as model
tools.

## 4. GitHub Actions and repository hardening

1. Declare permissions explicitly at workflow and job level; start with contents: read and grant each additional permission only to the job that requires it.
2. Pin third-party actions to full commit SHAs; verify the SHA belongs to the intended upstream release and record why it is trusted. Tags are mutable references.
3. Avoid secrets and write-capable tokens in workflows triggered by untrusted fork pull requests. Keep privileged post-merge/deployment workflows separate from untrusted build jobs.
4. Treat PR titles, issue text, branch names, generated files, downloaded artifacts and test output as untrusted input. Never interpolate them into shell commands without safe argument handling.
5. Use minimal checkout permissions, explicit artifact paths, bounded retention, and provenance metadata. Do not pass broad credentials through artifacts or caches.
6. Protect environment secrets with required reviewers and deployment branch restrictions where available.
7. Use OIDC for cloud federation where possible; constrain issuer, audience, repository, ref, environment and workflow identity at the target cloud. Avoid static cloud access keys.
8. Keep action dependencies and reusable workflow references pinned and reviewed. Monitor advisories and upstream changes.
9. Ensure cancellation, timeouts, concurrency groups and least-privilege permissions prevent duplicate or runaway deployment jobs.
10. Record workflow run ID, attempt, event type, triggering actor, commit SHA, artifact digest, status and deployment environment for release evidence.

GitHub's official guidance recommends minimum workflow-token permissions and full-length commit-SHA pinning for third-party actions. See the source register.

### Branch protection and rulesets

 Review whether the default/release branch requires pull requests, independent review, required status checks, conversation resolution, restrictions on force-push/deletion, signed commits or verified provenance where appropriate, and controlled bypass permissions. Protect workflow files and deployment environments. Settings depend on repository
ownership and plan. This report
does not assert that any specific setting is currently enabled; verify it in repository settings and through the GitHub API.

### GitHub App permissions

 Start with the minimum permission set required for each use case. A read-only evidence collector may need repository metadata, contents, pull requests, checks/actions read access; exact permission names depend on endpoints and webhook events. Do not request administration, contents-write, workflows-write, secrets-write, deployments-write or
organization permissions merely for
convenience.

Use a separate installation/app or separately reviewed privilege path for writes. Validate webhook signatures against the raw request body, enforce timestamp/replay protection, and deduplicate event deliveries.

## 5. GIEN evidence model

Store GitHub-derived facts as evidence records with fields such as:
- evidence_id, provider=GitHub, repository, commit_sha, path, line_range
- pull_request_number, workflow_run_id, run_attempt, check_name, conclusion
- observed_at, source_url, retrieval_method, parser_version
- content_hash only where lawful and useful; avoid storing duplicated full content when a stable source reference is sufficient
- classification, retention_class, tenant_id, authorization_context
- evidence_status: observed, validated, approved, superseded

Distinguish configured, executed, passed, reviewed and approved. A workflow definition is configured; a run record is executed; an actual successful conclusion is passed; an authorized reviewer decision is reviewed/approved. Never collapse these states.

Do not treat GitHub checks as proof that a production system is safe, a regulatory requirement is met, or GIEN systemic-risk values are below threshold. GitHub records can support software change assurance; runtime risk metrics require their own authoritative telemetry, versioned calculations and validation.

## 6. Rate limits, resilience and audit

- Honor primary and secondary rate limits and Retry-After/reset metadata. Use bounded exponential backoff with jitter and per-installation budgets.
- Paginate with explicit caps; use conditional requests/ETags where supported and useful.
- Cache only permitted, non-sensitive metadata, with tenant and permission-aware cache keys. Recheck authorization when serving cached results.
- Use circuit breakers and timeouts. Do not silently treat an API outage as a clean bill of health; return unknown/stale and surface data freshness.
- Separate webhook receipt from downstream processing using a durable queue, deduplicate delivery IDs and make handlers idempotent.
- Redact access tokens, private keys, webhook secrets, sensitive diff fragments and user PII from logs.
- Record denied writes as security audit events as well as successful actions.

## 7. Implementation sequence

**Phase 0 — Inventory:** enumerate repository, branch, app installation, workflow and deployment resources. Record current permissions, branch/ruleset settings, environments, required checks and secret inventory metadata (never secret values). Identify triggers that execute untrusted code and any write-capable token exposure.

**Phase 1 — Read-only evidence adapter:** add fixed operations for repository metadata, PRs, check runs and workflow summaries. Add evidence schema, provenance, freshness labels and access-denial tests. Use synthetic/private-safe fixtures in CI.

**Phase 2 — CI/release hardening:** audit workflow permissions, SHA pinning, fork PR behaviour, OIDC claims, environment protections, artifact retention and deployment boundaries. Change branch protection only after confirming required checks and authorized repository-admin access.

**Phase 3 — Approved workflow writes:** add issue/PR draft creation with explicit confirmation, strict schemas, allowlisted destinations, duplicate prevention and audit. Keep merge, release, permission changes, branch protection and deployment promotion out of general model tools.

**Phase 4 — Evidence export and evaluation:** produce a release evidence bundle with commit SHA, workflow IDs, check results, artifact digests and reviewer approvals. Test stale statuses, canceled runs, reruns, duplicate webhooks, revoked access, permission loss and GitHub outages.

## 8. Acceptance criteria

- [ ] Every GitHub operation maps to a documented fixed capability and minimal permission.
- [ ] Browser code contains no GitHub credentials; secret scanning passes.
- [ ] Webhooks verify signatures and reject replay/duplicate deliveries.
- [ ] Fork/untrusted PR workflows cannot access privileged deployment secrets or write-capable tokens.
- [ ] Third-party Actions are pinned to full commit SHAs and reviewed.
- [ ] CI status is retrieved from actual run/check records; absent or stale status is unknown, never passed.
- [ ] Tenant/repository/branch authorization is tested with negative cases.
- [ ] Write operations require server authorization and the appropriate human confirmation.
- [ ] Logs redact secrets and sensitive source content.
- [ ] Release evidence ties every claim to immutable commit/run identifiers and distinguishes configured, executed, passed and approved.

## 9. Official reference register

- GitHub Actions security hardening and secure use: <https://docs.GitHub.com/en/actions/reference/security/secure-use>
- Secure use of GitHub Actions: <https://docs.GitHub.com/en/actions/security-for-GitHub-actions/security-guides/security-hardening-for-GitHub-actions>
- GitHub App permission selection: <https://docs.GitHub.com/en/apps/creating-GitHub-apps/registering-a-GitHub-app/choosing-permissions-for-a-GitHub-app>
- Permissions required for GitHub Apps and REST API endpoints: <https://docs.GitHub.com/en/rest/authentication/permissions-required-for-GitHub-apps>
- Branch protection REST API: <https://docs.GitHub.com/en/rest/branches/branch-protection>
- Repository rulesets: <https://docs.GitHub.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets>
- GitHub Actions OIDC: <https://docs.GitHub.com/en/actions/security-for-GitHub-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect>
- GitHub REST API rate limits: <https://docs.GitHub.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api>
- Webhook validation: <https://docs.GitHub.com/en/webhooks/using-webhooks/validating-webhook-deliveries>

## 10. Limitations

 This is architecture guidance based on official public documentation and a limited repository metadata check on 12 October 2026. It is not a live audit of all repository settings, a security test, legal advice, or proof of independent assurance. GitHub product features and plan requirements can change. Verify settings and permissions in the target
account immediately before
implementation.