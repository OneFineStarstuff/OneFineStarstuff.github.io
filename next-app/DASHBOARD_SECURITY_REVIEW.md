# Sentinel Governance Dashboard — Security & Compliance Review

**Target:** `next-app/` (Next.js 16 / React 18 governance + risk console)
**Reviewer:** Sentinel assurance workstream
**Scope:** API route handlers (`app/api/**`), safety pipeline (`lib/safety`), consent
ledger (`lib/privacy`), and the risk console (`app/risk`). Static review only — no
authenticated runtime was available in the sandbox.
**Verdict:** The dashboard began as a **demonstration MVP**. As of this revision
**all eight findings (DASH‑01..08) are remediated**, covered by **16 passing
falsifiable tests** in `__tests__/dashboard_security_review.test.ts` (19/19 across the
whole next-app suite), and the new code typechecks clean (it also fixed the
pre-existing invalid TypeScript in `consentLedger.ts`).

> **Feasibility / status labelling** (consistent with the rest of the stack):
> Tier A = standards-grounded, fixable now. Each finding includes a minimal remediation.
> **Status legend:** Resolved = fixed in code + regression test; Open = not yet fixed.

### Remediation summary (this revision)
- Added `lib/auth/session.ts` — HMAC-signed session tokens; the authenticated
  principal is derived **server-side only** (Bearer header / `sentinel_session`
  cookie), never from client-supplied identity fields. Constant-time signature
  check; expiry enforced.
- Added `lib/http/guard.ts` — `readJson` enforces a 16 KiB body cap + safe parse;
  `sanitizeForStream` strips CR/LF/control chars to prevent SSE/log injection.
- Rewrote `app/api/consent/route.ts`, `app/api/chat/stream/route.ts`,
  `app/api/intent/route.ts` to use the above.
- **DASH-04:** `app/api/risk/scores/route.ts` now returns `synthetic: true` + a
  `DEMO DATA` disclaimer so synthetic series can't be mistaken for model output.
- **DASH-06:** `next.config.js` sets CSP + `X-Content-Type-Options` /
  `X-Frame-Options` / `Referrer-Policy` / HSTS; `middleware.ts` + `lib/http/rateLimit.ts`
  add per-client rate limiting on `/api/*` (120 req/min).
- **DASH-07:** `lib/privacy/consentLedger.ts` now **signs** each event hash
  (HMAC stand-in for the Dilithium/ML-DSA HSM signer), verifies the chain on
  export, and **fails closed** on `prevHash` read errors (no silent new chain).
- Added `app/api/auth/login/route.ts` — demo login issuing a signed, HttpOnly,
  SameSite=Strict `sentinel_session` cookie via `mintToken` (real IdP/OIDC in prod).
- `npx vitest run` → **19/19 pass** (16 security + 3 governance-remediation).

---

## Summary of findings

| ID | Severity | Component | Title | Status |
|----|----------|-----------|-------|--------|
| DASH-01 | High | `app/api/consent/route.ts` | Unauthenticated consent **export** of arbitrary `userId` (IDOR) | **Resolved** — authn + `canAccessSubject` authz |
| DASH-02 | High | `app/api/consent/route.ts` | Unauthenticated consent **write** (no session binding, spoofable `userId`) | **Resolved** — identity bound to principal |
| DASH-03 | High | `app/api/chat/stream/route.ts` | No authn/authz, no input size cap, unvalidated JSON body | **Resolved** — authn + 16 KiB cap; GET text-gen removed |
| DASH-04 | Medium | `app/api/risk/scores/route.ts` | Risk scores are `Math.random()` mock served from a governance surface | **Resolved** — `synthetic:true` + DEMO disclaimer |
| DASH-05 | Medium | `lib/safety/pipeline.ts` + chat route | Moderation `block` computed but **not enforced** | **Resolved** — block now suppresses reply |
| DASH-06 | Medium | All routes | No security headers / CSP / rate limiting / audit logging | **Resolved** — CSP+headers (next.config) + rate limit (middleware) |
| DASH-07 | Low | `lib/privacy/consentLedger.ts` | Hash chain present but no signature; `prevHash` swallow-on-error | **Resolved** — signed events; verify-on-export; fail-closed |
| DASH-08 | Low | `app/api/intent/route.ts` | Edge route reads unvalidated body; unbounded | **Resolved** — authn + body cap + validation |

---

## Detailed findings

### DASH-01 (High) — IDOR on consent export → GDPR Art. 15/32 exposure
`GET /api/consent?userId=<x>` calls `exportConsent(userId)` and returns the full
consent event chain for **any** `userId` with no authentication or ownership check:

```ts
export async function GET(req: NextRequest) {
  const userId = searchParams.get('userId') ?? 'demo';
  const data = await exportConsent(userId);   // <-- no authz
  return Response.json(data);
}
```

A consent ledger is personal data (lawful-basis evidence). Serving it to any caller is
an Insecure Direct Object Reference and a confidentiality breach.

**Remediation:** require an authenticated session; derive `userId` from the session
(never from the query string); authorize that the caller owns or has a DPO role over
the record. Mediate access through an OPA decision (`gdpr_ai_data_protection.rego`).

**Maps to:** GDPR Art. 15 (access), Art. 32 (security of processing); NIST AI RMF
GOVERN‑1.1; ISO/IEC 42001 A.7.

---

### DASH-02 (High) — Spoofable consent write defeats lawful-basis evidence
`POST /api/consent` accepts `userId` from the request body (`userId = 'demo'` default)
and appends a consent event with no session binding:

```ts
const { userId = 'demo', sessionId, action } = await req.json();
// action validated; userId/sessionId are caller-controlled and unauthenticated
const ev = await appendConsentEvent({ userId, sessionId, action, ... });
```

An attacker can forge "consent granted" / "consent withdrawn" events for another
subject, corrupting the very record used to prove GDPR lawful basis.

**Remediation:** bind `userId`/`sessionId` to the authenticated principal; reject
client-supplied identity fields; sign events server-side (see DASH-07).

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
frames; attach a request id for audit correlation.

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
`/api/intent` reads `message` and runs a regex. The regex is linear (no catastrophic
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
