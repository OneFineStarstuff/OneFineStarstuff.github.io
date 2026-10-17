# Sentinel Governance Dashboard — Security & Compliance Review

**Target:** `next-app/` (Next.js 16 / React 18 governance + risk console)
**Reviewer:** Sentinel assurance workstream
**Scope:** API route handlers (`app/api/**`), safety pipeline (`lib/safety`), consent
ledger (`lib/privacy`), and the risk console (`app/risk`). Static review only — no
authenticated runtime was available in the sandbox.
**Verdict:** The dashboard is a **demonstration MVP**, not production-ready for a
G‑SIFI deployment. Findings below are concrete, reproducible from the source, and
mapped to controls. None are theoretical.

> **Feasibility / status labelling** (consistent with the rest of the stack):
> Tier A = standards-grounded, fixable now. Each finding includes a minimal remediation.

---

## Summary of findings

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| DASH-01 | High | `app/api/consent/route.ts` | Consent export identity restriction | Constrained to demo-only mode; production auth pending |
| DASH-02 | High | `app/api/consent/route.ts` | Consent-write identity restriction | Constrained to demo-only mode; production auth pending |
| DASH-03 | High | `app/api/chat/stream/route.ts` | No authn/authz, no input size cap, unvalidated JSON body | Open |
| DASH-04 | Medium | `app/api/risk/scores/route.ts` | Risk scores are `Math.random()` mock served from a governance surface | Open (by design, must be labelled) |
| DASH-05 | Medium | `lib/safety/pipeline.ts` | Moderation is naive regular expression; `block` action is computed but **not enforced** | Open |
| DASH-06 | Medium | All routes | No security headers / CSP / rate limiting / audit logging | Open |
| DASH-07 | Low | `lib/privacy/consentLedger.ts` | Hash chain present but no signature; `prevHash` swallow-on-error | Open |
| DASH-08 | Low | `app/api/intent/route.ts` | Edge route reads unvalidated body; ReDoS-safe but unbounded | Open |

---

## Detailed findings

### DASH-01 (High; demo-mode guard added; production auth pending) — Consent export authorization

The route still accepts an optional `userId` query parameter for compatibility, but it now rejects values other than `demo` and always calls `exportConsent('demo')`. This blocks arbitrary-ID access in the demonstration build.

This is **not production-grade authorization**: no authenticated principal or ownership model is configured, and the demo ledger must not contain real personal data or be treated as a regulated consent record. Before production, derive identity from the authenticated server-side session and authorize access to the subject's own record (or a specific DPO role).

**Maps to:** GDPR Art. 15 (access), Art. 32 (security of processing); NIST AI RMF GOV-1.1; ISO/IEC 42001 A.7.

---

### DASH-02 (High; demo-mode guard added; production auth pending) — Consent-write identity restriction

The POST handler now validates that the request body is a JSON object, restricts `action` to the known action literals, bounds `sessionId`, and accepts only the fixed `demo` identity until authentication is implemented. It writes a fixed demo user ID rather than a caller-selected ID. Invalid JSON and malformed fields receive a 400 response; attempts to select a non-demo ID receive 403.

Because authentication is not configured, any caller may still modify the **shared demo ledger**. That ledger is not valid evidence of a real person's consent. Before production, bind user/session identifiers to an authenticated principal, reject client-supplied identity fields, and sign events server-side (see DASH-07).

**Maps to:** GDPR Art. 7 (conditions for consent), Art. 5(2) (accountability).

---

### DASH-03 (High) — Chat stream endpoint: no authn, no body limits
Both `POST` and `GET` handlers stream a model response from caller input with no
authentication, no rate limit, and no body-size cap:

```ts
export async function POST(req: NextRequest) {
  const { message } = await req.json();   // unbounded, unauthenticated
  return streamForMessage(message);
}
```

The `GET` variant also reflects `?q=` into the stream, widening the abuse surface
(CSRF-style invocation, log injection via SSE `data:` lines).

**Remediation:** authenticate; enforce `Content-Length`/timeout limits; remove the
`GET` text-generation path (use `POST` only); sanitize values before embedding in SSE
frames; attach a request ID for audit correlation.

**Maps to:** EU AI Act Annex IV §2(e) (cybersecurity/robustness); NIS2 Art. 21;
OWASP API Top‑10 (API4 unrestricted resource consumption, API2 broken authn).

---

### DASH-04 (Medium) — Random risk scores on a governance surface must be labelled
`GET /api/risk/scores` returns `30 + i*20 + sin(...) + Math.random()*10`. This is
fine for a UI demo, but a *governance* dashboard implies authority. Unlabelled mock
risk data could be mistaken for SR 11‑7 model output.

**Remediation:** flag the payload `"synthetic": true` and render a persistent
"DEMO DATA — not a validated model output" banner; wire to the real SARA/ACR + SRC‑1
proof feeds when available.

**Maps to:** SR 11‑7 (model output provenance); EU AI Act Art. 13 (transparency).

---

### DASH-05 (Medium) — Moderation decision computed but not enforced
`postModerate()` can return `{ action: 'block' }`, but `streamForMessage` enqueues the
reply regardless — the `post` event is attached to metadata and the content still
streams. The safety control is observability-only.

**Remediation:** branch on `post.action === 'block'` and suppress/replace the reply;
treat `revise` as a rewrite step; emit a tamper-evident moderation audit record.

**Maps to:** EU AI Act Art. 14 (human oversight) / Art. 15 (accuracy & robustness).

---

### DASH-06 (Medium) — Missing platform hardening
No security headers (CSP, `X-Content-Type-Options`, `Referrer-Policy`), no rate
limiting, no structured audit logging on any route.

**Remediation:** add `next.config` headers + middleware CSP; per-route rate limits;
forward security-relevant events to the PQC WORM logger
(`governance_artifacts/kafka/pqc_worm_logger_v2.py`).

**Maps to:** DORA Art. 9 (ICT protection); NIS2 Art. 21; ISO/IEC 42001 A.6.

---

### DASH-07 (Low) — Hash chain is integrity-only, not authenticity
`consentLedger.ts` chains events with SHA‑256 (`hash = H(fields | prevHash)`), which
detects tampering only if the verifier trusts the chain head. It is unsigned, so a
writer with file access can rewrite the entire chain consistently. Also, a read error
while fetching `prevHash` is swallowed (`catch { console.error }`), so a transient
failure silently starts a new chain.

**Remediation:** sign each event (or the chain head) with a KMS/HSM key — reuse the
CRYSTALS‑Dilithium signer from the WORM logger; fail-closed on `prevHash` read errors.

**Maps to:** GDPR Art. 5(2)/Art. 30 (records of processing integrity).

---

### DASH-08 (Low) — Edge intent route: unbounded, unvalidated body
`/api/intent` reads `message` and runs a regular expression. The expression is linear (no catastrophic
backtracking), but the body is unbounded and unauthenticated.

**Remediation:** cap body size; authenticate; return `400` on missing `message`.

---

## What the dashboard does *right* (kept as-is)
- Server-side safety **pipeline module exists and is unit-testable** (regexes are
  ReDoS-safe; logic is pure functions — good for `vitest`).
- Consent events form a **hash-linked ledger** — the right shape for GDPR evidence;
  it only needs authentication + signatures to be production-grade.
- Clear layer separation (`lib/ai`, `lib/safety`, `lib/privacy`, `lib/telemetry`).

## Recommended remediation order
1. **DASH-01 / DASH-02** (consent authz + identity binding) — privacy-critical.
2. **DASH-03** (chat endpoint authn + limits) — largest abuse surface.
3. **DASH-05** (enforce moderation block) — safety control must be enforcing.
4. **DASH-04 / DASH-06 / DASH-07 / DASH-08** — hardening + labelling.

All four High/Medium-priority fixes are Tier A (buildable now with Next.js
middleware + the existing OPA policies and Dilithium signer in this repo).
