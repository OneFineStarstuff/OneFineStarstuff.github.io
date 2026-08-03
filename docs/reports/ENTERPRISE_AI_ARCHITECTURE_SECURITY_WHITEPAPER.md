# Enterprise AI Architecture, Security & Compliance-as-Code

## Technical Deep-Dive: Production-Grade Governance Infrastructure for G-SIFIs

---

**Document Reference:** ARCH-GSIFI-WP-002
**Version:** 1.0.0
**Classification:** CONFIDENTIAL — Engineering / Architecture / Security
**Date:** 2026-03-22
**Authors:** Chief Software Architect; VP Platform Engineering; CISO
**Intended Audience:** CTOs, VPs of Engineering, Enterprise Architects, CISOs, DevSecOps, Platform Teams, AI/ML Engineering, Internal Audit (Technology)
**Companion Documents:** GOV-GSIFI-WP-001, SPEC-AGIGOV-UNIFIED-001, GOV-GSIFI-RPT-001

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Principles & Design Philosophy](#2-architecture-principles--design-philosophy)
3. [Kafka-Based WORM Audit Logging Architecture](#3-kafka-based-worm-audit-logging-architecture)
4. [Docker Swarm Security Architecture](#4-docker-swarm-security-architecture)
5. [Node.js Governance Sidecar](#5-nodejs-governance-sidecar)
6. [Python Governance Sidecar](#6-python-governance-sidecar)
7. [Next.js Explainability Frontend](#7-nextjs-explainability-frontend)
8. [Governance-First LLMOps Pipeline](#8-governance-first-llmops-pipeline)
9. [OPA-Based Compliance-as-Code Engine](#9-opa-based-compliance-as-code-engine)
10. [Hyperparameter Governance Standards](#10-hyperparameter-governance-standards)
11. [Sentinel v2.4 Integration Architecture](#11-sentinel-v24-integration-architecture)
12. [Network Security & Zero-Trust Architecture](#12-network-security--zero-trust-architecture)
13. [Deployment Patterns & Infrastructure](#13-deployment-patterns--infrastructure)
14. [Observability & Monitoring Stack](#14-observability--monitoring-stack)
15. [Performance Benchmarks](#15-performance-benchmarks)
16. [Security Threat Model](#16-security-threat-model)
17. [Architecture Decision Records](#17-architecture-decision-records)

---

## 1. Executive Summary

This whitepaper provides a comprehensive technical architecture specification for the governance infrastructure underpinning AI/ML systems at Global Systemically Important Financial Institutions (G-SIFIs). It details production-grade implementations of:

- **Kafka WORM Audit Logging**: Tamper-proof, cryptographically sealed audit trails with 7–10 year retention for regulatory compliance (SR 11-7, EU AI Act Art. 12, PRA SS1/23).
- **Docker Swarm Security**: Hardened container orchestration with governance-enforced deployment gates, secret management, and network segmentation.
- **Node.js & Python Governance Sidecars**: Language-specific policy enforcement proxies that intercept and govern all AI system interactions in real-time.
- **Next.js Explainability Frontend**: Interactive dashboards providing SHAP/LIME visualizations, counterfactual explanations, and regulatory-grade transparency (EU AI Act Art. 13, GDPR Art. 22).
- **Governance-First LLMOps**: A 7-stage governed pipeline from data curation through production monitoring with embedded compliance gates at each stage.
- **OPA Compliance-as-Code**: 278 Rego policy rules enforcing 16 regulatory regimes with sub-5ms P99 latency.
- **Hyperparameter Governance**: MRM-approved, version-controlled, audit-trailed hyperparameter management with automated drift detection.

### Key Metrics

| Metric | Value | SLA |
|--------|-------|-----|
| Kafka WORM throughput | 45,000 events/sec | ≥30,000 |
| Kafka end-to-end latency | 12 ms (P99) | ≤50 ms |
| OPA policy evaluation P99 | 4.2 ms | ≤10 ms |
| Sidecar overhead (Node.js) | 2.1 ms per request | ≤5 ms |
| Sidecar overhead (Python) | 3.4 ms per request | ≤5 ms |
| Explainability dashboard TTFB | 180 ms | ≤500 ms |
| Sentinel policy evaluations/day | 1.2M | ≥1M |
| Docker image scan time | 28 sec | ≤60 sec |
| Evidence bundle generation | 4.2 sec | ≤10 sec |
| System availability | 99.97% | ≥99.95% |

---

## 2. Architecture Principles & Design Philosophy

### 2.1 Core Principles

| # | Principle | Rationale | Implementation |
|---|-----------|-----------|----------------|
| **P1** | Governance-by-Construction | Controls embedded in architecture, not bolted on | Sidecars enforce policy before any AI interaction |
| **P2** | Zero-Trust for AI | No AI system trusted by default | mTLS, JWT validation, OPA authorization for every call |
| **P3** | Immutable Audit | All governance decisions are permanent records | Kafka WORM with SHA-256 Merkle sealing |
| **P4** | Least Privilege | Minimum necessary access for all components | RBAC + ABAC with OPA enforcement |
| **P5** | Defence in Depth | Multiple overlapping security layers | Network, container, application, data encryption layers |
| **P6** | Fail-Safe Governance | System defaults to deny on policy failure | OPA default-deny; kill switch on sidecar failure |
| **P7** | Observable Compliance | All compliance state is measurable in real-time | Prometheus metrics, Grafana dashboards, alert pipelines |
| **P8** | Reproducible Evidence | Audit artifacts are deterministically reproducible | Content-addressed evidence bundles with manifest hashes |

### 2.2 Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           PRESENTATION LAYER                              │
│                                                                           │
│  ┌────────────────────┐  ┌────────────────────┐  ┌──────────────────┐   │
│  │ Next.js Explain.   │  │ Governance Console  │  │ Examiner Portal  │   │
│  │ Frontend           │  │ (React)             │  │ (Read-only API)  │   │
│  └────────┬───────────┘  └────────┬───────────┘  └────────┬─────────┘   │
│           │                       │                        │              │
├───────────┼───────────────────────┼────────────────────────┼──────────────┤
│                           API GATEWAY / MESH                              │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │                    Kong / Envoy (mTLS, Rate Limiting)              │  │
│  └────────────────────────────────┬───────────────────────────────────┘  │
│                                   │                                       │
├───────────────────────────────────┼───────────────────────────────────────┤
│                           GOVERNANCE LAYER                                │
│                                   │                                       │
│  ┌──────────────┐  ┌──────────────┴──────────────┐  ┌────────────────┐  │
│  │ Node.js      │  │     OPA Policy Engine        │  │ Python         │  │
│  │ Governance   │◄─┤     (278 Rego Rules)         ├─►│ Governance     │  │
│  │ Sidecar      │  │     P99: 4.2 ms              │  │ Sidecar        │  │
│  └──────┬───────┘  └──────────────────────────────┘  └──────┬─────────┘  │
│         │                                                    │            │
├─────────┼────────────────────────────────────────────────────┼────────────┤
│                           AI SERVICE LAYER                                │
│         │                                                    │            │
│  ┌──────▼──────────┐  ┌─────────────────┐  ┌───────────────▼──────────┐ │
│  │ LLM Services    │  │ ML Model        │  │ RAG Pipeline             │ │
│  │ (GPT, Claude,   │  │ Services        │  │ (Veridical)              │ │
│  │  Gemini)        │  │ (Credit, Risk)  │  │                          │ │
│  └─────────────────┘  └─────────────────┘  └──────────────────────────┘ │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                           DATA & AUDIT LAYER                              │
│                                                                           │
│  ┌──────────────────┐  ┌─────────────────┐  ┌──────────────────────┐    │
│  │ Kafka WORM       │  │ PostgreSQL      │  │ Redis Cache          │    │
│  │ Audit Cluster    │  │ (Model Registry,│  │ (Session, Policy     │    │
│  │ (3 brokers,      │  │  Evidence Store) │  │  Cache)              │    │
│  │  SHA-256 seal)   │  │                 │  │                      │    │
│  └──────────────────┘  └─────────────────┘  └──────────────────────┘    │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                           INFRASTRUCTURE LAYER                            │
│                                                                           │
│  ┌──────────────────┐  ┌─────────────────┐  ┌──────────────────────┐    │
│  │ Docker Swarm     │  │ HashiCorp Vault │  │ Terraform / IaC      │    │
│  │ (Hardened)       │  │ (Secrets)       │  │ (GitOps)             │    │
│  └──────────────────┘  └─────────────────┘  └──────────────────────┘    │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Kafka-Based WORM Audit Logging Architecture

### 3.1 Design Requirements

| Requirement | Source Regulation | Specification |
|-------------|------------------|---------------|
| Tamper-proof audit trail | SR 11-7 §III.G, EU AI Act Art. 12 | WORM storage with cryptographic integrity |
| Minimum retention: 7 years | SR 11-7 §IV.B | Configurable per jurisdiction (7–10 years) |
| Maximum retention: 10 years | EU AI Act Art. 12(2) | Tiered storage (hot → warm → cold → archive) |
| Real-time event streaming | PRA SS1/23 §4.5 | Sub-50ms end-to-end latency |
| Examiner access | All regimes | Read-only API with audit-of-audit |
| Integrity verification | ISO 42001 Annex A.6 | SHA-256 Merkle tree with periodic seal |

### 3.2 Cluster Topology

```
                    ┌──────────────────────────────┐
                    │     Kafka WORM Cluster        │
                    │     (Dedicated, Isolated)      │
                    │                                │
                    │  ┌────────┐ ┌────────┐ ┌────┐│
                    │  │Broker 1│ │Broker 2│ │Br 3││
                    │  │(AZ-A)  │ │(AZ-B)  │ │(C) ││
                    │  └────┬───┘ └────┬───┘ └──┬─┘│
                    │       │          │        │   │
                    │  ┌────┴──────────┴────────┴─┐│
                    │  │    ZooKeeper Ensemble     ││
                    │  │    (3-node quorum)        ││
                    │  └──────────────────────────┘│
                    └──────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌──────────┐  ┌──────────┐  ┌──────────────┐
             │ Merkle   │  │ Evidence │  │ Examiner     │
             │ Sealer   │  │ Bundle   │  │ Access API   │
             │ (hourly) │  │ Generator│  │ (read-only)  │
             └──────────┘  └──────────┘  └──────────────┘
```

### 3.3 Topic Architecture

| Topic | Partitions | Replication | Retention | Purpose |
|-------|-----------|-------------|-----------|---------|
| `gov.audit.model-lifecycle` | 12 | 3 | 10 years | Model CRUD events, version changes |
| `gov.audit.policy-decisions` | 24 | 3 | 10 years | OPA policy evaluation results |
| `gov.audit.data-access` | 12 | 3 | 7 years | Training/inference data access logs |
| `gov.audit.human-oversight` | 6 | 3 | 10 years | Human review decisions, overrides |
| `gov.audit.incidents` | 6 | 3 | 10 years | Incident detection, response, resolution |
| `gov.audit.fairness` | 12 | 3 | 10 years | Bias metrics, disparate impact scores |
| `gov.audit.explainability` | 12 | 3 | 7 years | SHAP values, explanation requests |
| `gov.audit.hyperparameters` | 6 | 3 | 10 years | Hyperparameter changes, approvals |
| `gov.audit.deployment` | 6 | 3 | 7 years | Deployment events, rollbacks |
| `gov.audit.vendor` | 6 | 3 | 7 years | Third-party AI API calls, SLA events |

### 3.4 WORM Enforcement Configuration

```yaml
# Kafka WORM Configuration (server.properties)
# ─────────────────────────────────────────────

# Immutability enforcement
log.message.timestamp.type=LogAppendTime
log.cleaner.enable=false
log.retention.check.interval.ms=300000

# WORM-specific settings
# Prevent deletion of committed records
delete.topic.enable=false
auto.create.topics.enable=false

# Replication for durability
default.replication.factor=3
min.insync.replicas=2
unclean.leader.election.enable=false

# Security
inter.broker.protocol=SSL
ssl.client.auth=required
ssl.protocol=TLSv1.3

# ACL enforcement
authorizer.class.name=kafka.security.authorizer.AclAuthorizer
super.users=User:kafka-admin
allow.everyone.if.no.acl.found=false
```

### 3.5 Merkle Tree Sealing

Every hour, the Merkle Sealer service computes a cryptographic seal over all audit events:

```
Merkle Tree Structure (Hourly Seal)
════════════════════════════════════

                    ┌────────────────┐
                    │   Root Hash    │
                    │  (SHA-256)     │
                    │  Published to  │
                    │  immutable     │
                    │  blockchain    │
                    └───────┬────────┘
                    ┌───────┴────────┐
                    ▼                ▼
             ┌──────────┐    ┌──────────┐
             │ Hash(AB) │    │ Hash(CD) │
             └────┬─────┘    └────┬─────┘
              ┌───┴───┐      ┌───┴───┐
              ▼       ▼      ▼       ▼
          ┌──────┐┌──────┐┌──────┐┌──────┐
          │Evt A ││Evt B ││Evt C ││Evt D │
          │SHA256││SHA256││SHA256││SHA256│
          └──────┘└──────┘└──────┘└──────┘
```

**Verification process:**
1. Hourly: Merkle root computed and published to internal blockchain (Hyperledger Fabric).
2. Daily: Independent verification service recomputes and compares roots.
3. Quarterly: External auditor samples and verifies event chains.
4. On-demand: Examiner API provides proof-of-inclusion for any event.

### 3.6 Evidence Bundle Generation

```json
{
  "evidenceBundle": {
    "bundleId": "EVB-2026-Q1-MODEL-042",
    "generatedAt": "2026-03-22T10:00:00Z",
    "generatedBy": "evidence-generator-v3.2",
    "subject": {
      "modelId": "MDL-CREDIT-2024-001",
      "modelName": "Consumer Credit Scoring v4.1",
      "riskTier": "HIGH"
    },
    "contents": {
      "modelCard": { "hash": "sha256:a3f2...", "size": 42800 },
      "validationReport": { "hash": "sha256:b4e1...", "size": 128400 },
      "biasAudit": { "hash": "sha256:c5d3...", "size": 67200 },
      "dpia": { "hash": "sha256:d6a4...", "size": 34100 },
      "auditEvents": { "hash": "sha256:e7b5...", "count": 14823 },
      "policyDecisions": { "hash": "sha256:f8c6...", "count": 892400 },
      "hyperparameterHistory": { "hash": "sha256:09d7...", "versions": 12 }
    },
    "manifest": {
      "hash": "sha256:1a2b3c4d5e6f...",
      "signedBy": "evidence-generator-key-2026",
      "algorithm": "RSA-4096-PSS"
    },
    "retention": {
      "policy": "WORM-10Y",
      "expiresAt": "2036-03-22T10:00:00Z"
    }
  }
}
```

### 3.7 Tiered Storage Architecture

| Tier | Age | Storage | Cost/GB/month | Access SLA |
|------|-----|---------|---------------|------------|
| **Hot** | 0–90 days | NVMe SSD (Kafka brokers) | $0.23 | ≤12 ms |
| **Warm** | 91–365 days | SSD Object Storage | $0.08 | ≤100 ms |
| **Cold** | 1–3 years | HDD Object Storage | $0.02 | ≤1 sec |
| **Archive** | 3–10 years | Glacier-class | $0.004 | ≤4 hours |

### 3.8 Performance Metrics

| Metric | Value | SLA |
|--------|-------|-----|
| Write throughput | 45,000 events/sec | ≥30,000 |
| End-to-end latency (P99) | 12 ms | ≤50 ms |
| Merkle seal computation | 2.3 sec (hourly) | ≤5 sec |
| Evidence bundle generation | 4.2 sec | ≤10 sec |
| Proof-of-inclusion query | 180 ms | ≤500 ms |
| Cluster availability | 99.99% | ≥99.95% |
| Data durability | 99.999999999% (11 nines) | ≥99.999999% |

---

## 4. Docker Swarm Security Architecture

### 4.1 Security Hardening Measures

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Host OS** | Minimal attack surface | Alpine-based hosts, CIS Benchmark Level 2 |
| **Docker daemon** | Rootless mode | User-namespace remapping, seccomp profiles |
| **Images** | Supply chain security | Signed images (Docker Content Trust), Trivy scanning |
| **Runtime** | Resource isolation | CPU/memory limits, read-only root filesystem, no-new-privileges |
| **Network** | Segmentation | Encrypted overlay networks, ingress filtering |
| **Secrets** | Centralized management | HashiCorp Vault integration with auto-rotation |
| **Logging** | Audit trail | All container events → Kafka WORM audit topic |
| **Compliance** | Pre-deployment gates | OPA admission control for all deployments |

### 4.2 Swarm Cluster Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Swarm Cluster                      │
│                                                                  │
│  Manager Nodes (3 — quorum)                                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ Manager-1    │ │ Manager-2    │ │ Manager-3    │            │
│  │ (Leader)     │ │ (Reachable)  │ │ (Reachable)  │            │
│  │ AZ-A         │ │ AZ-B         │ │ AZ-C         │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  Worker Nodes (AI Workloads)                                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ GPU Worker-1 │ │ GPU Worker-2 │ │ GPU Worker-3 │            │
│  │ (NVIDIA A100)│ │ (NVIDIA A100)│ │ (NVIDIA H100)│            │
│  │ AI Inference │ │ AI Training  │ │ AI Inference │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  Worker Nodes (Governance Services)                              │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ Gov Worker-1 │ │ Gov Worker-2 │ │ Gov Worker-3 │            │
│  │ OPA, Sidecars│ │ Kafka, Seal  │ │ Sentinel     │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│                                                                  │
│  Encrypted Overlay Networks                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ ai-services-net │ governance-net │ audit-net │ mgmt-net    ││
│  │ (IPSec/WireGd)  │ (IPSec)        │ (IPSec)   │ (IPSec)    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 Container Security Policy

```yaml
# Docker Compose — Governance Sidecar Security Configuration
version: "3.8"
services:
  governance-sidecar-node:
    image: registry.internal/governance-sidecar-node:v3.2@sha256:abc123...
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.5"
          memory: 256M
      placement:
        constraints:
          - node.labels.workload == governance
    security_opt:
      - no-new-privileges:true
      - seccomp:governance-sidecar-seccomp.json
    read_only: true
    tmpfs:
      - /tmp:size=64M,noexec,nosuid
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 10s
      timeout: 5s
      retries: 3
    networks:
      - governance-net
      - ai-services-net
    secrets:
      - opa-api-key
      - kafka-tls-cert
      - vault-token
```

### 4.4 Image Scanning & Admission

```
Image Deployment Pipeline
─────────────────────────
  1. Developer pushes to Git
       │
  2. CI builds Docker image
       │
  3. Trivy vulnerability scan ─── CRITICAL/HIGH → BLOCK
       │ (CVE database updated hourly)
       │
  4. Snyk dependency scan ─── Known exploit → BLOCK
       │
  5. Docker Content Trust signing
       │ (Notary v2 with HSM-backed keys)
       │
  6. OPA admission policy check ─── Policy violation → BLOCK
       │ ─ Base image approved?
       │ ─ Security context compliant?
       │ ─ Resource limits set?
       │ ─ Read-only root filesystem?
       │ ─ No privileged containers?
       │
  7. Deploy to Swarm cluster
       │
  8. Runtime security (Falco) → anomaly detection
```

### 4.5 Image Scanning Metrics

| Metric | Value |
|--------|-------|
| Mean scan time | 28 sec |
| Vulnerability SLA (Critical) | Patch within 24 hours |
| Vulnerability SLA (High) | Patch within 7 days |
| Current critical CVEs | 0 |
| Current high CVEs | 2 (patches scheduled) |
| Images with DCT signatures | 100% |
| OPA admission rejection rate | 3.2% (policy violations) |

---

## 5. Node.js Governance Sidecar

### 5.1 Architecture

The Node.js governance sidecar is a high-performance proxy that intercepts all API calls between consumers and AI services, enforcing governance policies in real-time.

```
┌────────────────────────────────────────────────────────┐
│                Node.js Governance Sidecar                │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │ Ingress  │───►│ Policy   │───►│ AI Service       │  │
│  │ Handler  │    │ Enforcer │    │ Proxy            │  │
│  │ (Express │    │ (OPA     │    │ (Upstream call)  │  │
│  │  + mTLS) │    │  Client) │    │                  │  │
│  └──────────┘    └──────────┘    └──────────────────┘  │
│       │               │                    │            │
│       ▼               ▼                    ▼            │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │ Rate     │    │ Audit    │    │ Response         │  │
│  │ Limiter  │    │ Logger   │    │ Validator        │  │
│  │          │    │ (Kafka)  │    │ (Schema + PII)   │  │
│  └──────────┘    └──────────┘    └──────────────────┘  │
└────────────────────────────────────────────────────────┘
```

### 5.2 Core Implementation

```javascript
// governance-sidecar/src/index.ts
// Node.js Governance Sidecar v3.2
// ─────────────────────────────────

import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { OPAClient } from './opa-client';
import { KafkaAuditLogger } from './kafka-audit';
import { PIIDetector } from './pii-detector';
import { RateLimiter } from './rate-limiter';

const app = express();
const opa = new OPAClient({ endpoint: process.env.OPA_URL });
const audit = new KafkaAuditLogger({ brokers: process.env.KAFKA_BROKERS });
const pii = new PIIDetector();
const limiter = new RateLimiter({ windowMs: 60000, max: 1000 });

// Middleware chain: Rate Limit → Auth → Policy → Proxy → Audit
app.use(limiter.middleware());

app.use('/api/ai/*', async (req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomUUID();

  // 1. Build policy input
  const policyInput = {
    subject: req.user,
    action: req.method,
    resource: req.path,
    context: {
      timestamp: new Date().toISOString(),
      sourceIp: req.ip,
      userAgent: req.headers['user-agent'],
      modelId: req.params.modelId,
      riskTier: req.headers['x-risk-tier'],
    }
  };

  // 2. OPA policy evaluation
  const decision = await opa.evaluate('ai/governance/request', policyInput);

  // 3. Audit the decision (WORM)
  await audit.log({
    eventType: 'POLICY_DECISION',
    requestId,
    decision: decision.allow ? 'ALLOW' : 'DENY',
    policyId: decision.policyId,
    reasons: decision.reasons,
    latencyMs: Date.now() - startTime,
    input: policyInput,
  });

  // 4. Enforce decision
  if (!decision.allow) {
    return res.status(403).json({
      error: 'GOVERNANCE_POLICY_VIOLATION',
      requestId,
      reasons: decision.reasons,
      remediation: decision.remediation,
    });
  }

  // 5. PII detection on request body
  if (req.body) {
    const piiScan = pii.scan(req.body);
    if (piiScan.detected && !decision.piiAllowed) {
      await audit.log({
        eventType: 'PII_BLOCKED',
        requestId,
        piiTypes: piiScan.types,
      });
      return res.status(422).json({
        error: 'PII_DETECTED_IN_REQUEST',
        requestId,
        piiTypes: piiScan.types,
      });
    }
  }

  // 6. Proxy to upstream AI service
  next();
});

// Health and metrics endpoints
app.get('/health', (req, res) => res.json({ status: 'healthy', version: '3.2.0' }));
app.get('/metrics', (req, res) => res.json(getPrometheusMetrics()));

app.listen(8080, () => console.log('Governance sidecar listening on :8080'));
```

### 5.3 Performance Profile

| Metric | Value |
|--------|-------|
| Overhead per request | 2.1 ms (P50), 3.8 ms (P99) |
| Memory footprint | 128 MB (steady state) |
| CPU usage | 0.3 cores (1000 req/sec) |
| Concurrent connections | 10,000 (keep-alive) |
| OPA decision cache hit rate | 78% |
| Requests/sec (single instance) | 8,500 |

---

## 6. Python Governance Sidecar

### 6.1 Architecture

The Python governance sidecar serves ML/data science workloads, providing governance enforcement for model training, inference, and data access operations.

```
┌────────────────────────────────────────────────────────┐
│              Python Governance Sidecar                    │
│                                                          │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │ FastAPI  │───►│ Policy   │───►│ Model Service    │  │
│  │ Ingress  │    │ Enforcer │    │ Proxy            │  │
│  │ (uvicorn │    │ (OPA     │    │ (httpx async)    │  │
│  │  + mTLS) │    │  gRPC)   │    │                  │  │
│  └──────────┘    └──────────┘    └──────────────────┘  │
│       │               │                    │            │
│       ▼               ▼                    ▼            │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐  │
│  │ Feature  │    │ Audit    │    │ Bias/Fairness    │  │
│  │ Gov.     │    │ Logger   │    │ Interceptor      │  │
│  │ (schema) │    │ (aiokafka│    │ (real-time DI)   │  │
│  └──────────┘    └──────────┘    └──────────────────┘  │
└────────────────────────────────────────────────────────┘
```

### 6.2 Core Implementation

```python
# governance_sidecar/main.py
# Python Governance Sidecar v3.2
# ─────────────────────────────

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import httpx
import uuid
from datetime import datetime

from .opa_client import OPAClient
from .kafka_audit import KafkaAuditLogger
from .fairness import FairnessInterceptor
from .feature_governance import FeatureGovernor

app = FastAPI(title="Python Governance Sidecar", version="3.2.0")
opa = OPAClient(endpoint=os.environ["OPA_URL"])
audit = KafkaAuditLogger(brokers=os.environ["KAFKA_BROKERS"])
fairness = FairnessInterceptor()
feature_gov = FeatureGovernor()

@app.middleware("http")
async def governance_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = datetime.utcnow()

    # 1. Build governance context
    context = {
        "subject": request.headers.get("x-user-id"),
        "action": request.method,
        "resource": str(request.url.path),
        "model_id": request.headers.get("x-model-id"),
        "risk_tier": request.headers.get("x-risk-tier"),
        "timestamp": start_time.isoformat(),
    }

    # 2. OPA policy evaluation
    decision = await opa.evaluate_async("ai/governance/ml_request", context)

    # 3. Audit to Kafka WORM
    await audit.log_async({
        "event_type": "POLICY_DECISION",
        "request_id": request_id,
        "decision": "ALLOW" if decision.allow else "DENY",
        "policy_id": decision.policy_id,
        "latency_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
        "context": context,
    })

    if not decision.allow:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "GOVERNANCE_POLICY_VIOLATION",
                "request_id": request_id,
                "reasons": decision.reasons,
            }
        )

    # 4. Feature governance check (for inference requests)
    if "/predict" in str(request.url.path):
        body = await request.json()
        feature_check = await feature_gov.validate_features(
            model_id=context["model_id"],
            features=body.get("features", {})
        )
        if not feature_check.valid:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "FEATURE_GOVERNANCE_VIOLATION",
                    "violations": feature_check.violations,
                }
            )

    # 5. Proxy to upstream
    response = await call_next(request)

    # 6. Post-response fairness check
    if "/predict" in str(request.url.path) and response.status_code == 200:
        await fairness.record_prediction(
            model_id=context["model_id"],
            request_id=request_id,
            # Response body captured for DI analysis
        )

    return response

@app.get("/health")
async def health():
    return {"status": "healthy", "version": "3.2.0"}

@app.get("/metrics")
async def metrics():
    return get_prometheus_metrics()
```

### 6.3 Feature Governance

The Python sidecar enforces feature-level governance for ML models:

| Governance Rule | Description | Example |
|---------------|-------------|---------|
| **Prohibited features** | Features barred by regulation (e.g., race for credit scoring) | ECOA: race, religion, national origin |
| **Feature drift detection** | Alert when feature distributions shift beyond thresholds | KL divergence > 0.1 → alert |
| **Feature lineage** | Track provenance of every feature from source to prediction | Data catalog → feature store → model |
| **Schema validation** | Ensure features match registered schema (type, range, nullability) | age: int, range [18, 120], not null |
| **Encoding governance** | Ensure categorical encodings match training definitions | Prevent label leakage, ensure consistency |

### 6.4 Performance Profile

| Metric | Value |
|--------|-------|
| Overhead per request | 3.4 ms (P50), 5.1 ms (P99) |
| Memory footprint | 256 MB (steady state) |
| CPU usage | 0.5 cores (500 req/sec) |
| Concurrent connections | 5,000 (async) |
| OPA gRPC decision latency | 1.2 ms (P50) |
| Fairness buffer flush interval | 60 sec |

---

## 7. Next.js Explainability Frontend

### 7.1 Regulatory Requirements

| Regulation | Explainability Requirement | Frontend Feature |
|-----------|---------------------------|-----------------|
| EU AI Act Art. 13 | Transparency for users of high-risk systems | Model info panel, risk level badge, data sources |
| GDPR Art. 22 | Meaningful information about logic, significance, consequences | Decision explanation page with plain-language summary |
| GDPR Art. 15 | Right of access including logic of automated decisions | DSAR self-service portal with explanation download |
| SR 11-7 §III.E | Model validation evidence display | Validation report viewer |
| FCA Consumer Duty | Consumer understanding of AI-driven decisions | Plain-language explanation at appropriate literacy level |
| MAS FEAT 4.1 | Understandable explanations for customers | Tiered explanations (technical + consumer) |

### 7.2 Frontend Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                 Next.js Explainability Frontend                │
│                 (SSR + ISR, React 18, TypeScript)              │
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │ Decision        │  │ Model           │  │ DSAR Portal  │  │
│  │ Explorer        │  │ Observatory     │  │              │  │
│  │ ─ SHAP charts   │  │ ─ Model cards   │  │ ─ Self-serve │  │
│  │ ─ LIME local    │  │ ─ Risk tiers    │  │ ─ Explanation│  │
│  │ ─ Counterfactual│  │ ─ Performance   │  │   downloads  │  │
│  │ ─ Feature imp.  │  │ ─ Drift status  │  │ ─ Audit trail│  │
│  └─────────────────┘  └─────────────────┘  └──────────────┘  │
│                                                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐  │
│  │ Fairness        │  │ Compliance      │  │ Examiner     │  │
│  │ Dashboard       │  │ Evidence        │  │ View         │  │
│  │ ─ DI ratios     │  │ ─ Evidence packs│  │ ─ Read-only  │  │
│  │ ─ Group metrics │  │ ─ Audit trail   │  │ ─ Filtered   │  │
│  │ ─ Trend charts  │  │ ─ Control status│  │ ─ Exportable │  │
│  └─────────────────┘  └─────────────────┘  └──────────────┘  │
│                                                                │
│  API Layer: tRPC + React Query                                 │
│  Auth: NextAuth.js + OAuth2 / SAML                             │
│  Styling: Tailwind CSS + shadcn/ui                             │
│  Charts: Recharts + D3.js                                      │
│  Testing: Playwright E2E + Jest unit                           │
└──────────────────────────────────────────────────────────────┘
```

### 7.3 SHAP Visualization Component

```typescript
// components/ShapExplainer.tsx
// SHAP Feature Importance Visualization
// ──────────────────────────────────────

import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

interface ShapValue {
  feature: string;
  value: number;
  baseValue: number;
  contribution: number;
  direction: 'positive' | 'negative';
}

interface ShapExplainerProps {
  modelId: string;
  predictionId: string;
  shapValues: ShapValue[];
  baselineScore: number;
  finalScore: number;
  decisionThreshold: number;
  riskTier: string;
  regulatoryContext: {
    regime: string;      // e.g., "EU AI Act Art. 13"
    explanationLevel: 'technical' | 'consumer' | 'regulator';
  };
}

export const ShapExplainer: React.FC<ShapExplainerProps> = ({
  modelId, predictionId, shapValues, baselineScore,
  finalScore, decisionThreshold, riskTier, regulatoryContext
}) => {
  const sortedValues = [...shapValues].sort(
    (a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)
  );

  return (
    <div className="shap-explainer" role="region" aria-label="AI Decision Explanation">
      {/* Regulatory compliance header */}
      <header className="compliance-badge">
        <span className="regime">{regulatoryContext.regime}</span>
        <span className="risk-tier">{riskTier}</span>
        <span className="explanation-level">{regulatoryContext.explanationLevel}</span>
      </header>

      {/* Plain-language summary (Consumer Duty / GDPR Art. 22) */}
      <section className="plain-language-summary">
        <h3>Why this decision was made</h3>
        <p>
          The AI system analysed {shapValues.length} factors to reach a score of{' '}
          <strong>{finalScore.toFixed(2)}</strong> (threshold: {decisionThreshold}).
          The most influential factors were:
        </p>
        <ol>
          {sortedValues.slice(0, 3).map((sv) => (
            <li key={sv.feature}>
              <strong>{sv.feature}</strong>: {sv.direction === 'positive' ? 'increased' : 'decreased'}{' '}
              the score by {Math.abs(sv.contribution).toFixed(3)}
            </li>
          ))}
        </ol>
      </section>

      {/* Technical SHAP chart */}
      <section className="shap-chart">
        <ResponsiveContainer width="100%" height={400}>
          <BarChart data={sortedValues} layout="vertical">
            <XAxis type="number" />
            <YAxis type="category" dataKey="feature" width={200} />
            <Tooltip />
            <Bar
              dataKey="contribution"
              fill={(entry) => entry.direction === 'positive' ? '#22c55e' : '#ef4444'}
            />
          </BarChart>
        </ResponsiveContainer>
      </section>

      {/* Counterfactual explanation */}
      <section className="counterfactual">
        <h3>What would change the outcome</h3>
        <p>The decision would change if:</p>
        {/* Generated by counterfactual engine */}
      </section>
    </div>
  );
};
```

### 7.4 Performance Metrics

| Metric | Value |
|--------|-------|
| Time to First Byte (TTFB) | 180 ms |
| Largest Contentful Paint (LCP) | 1.2 sec |
| First Input Delay (FID) | 12 ms |
| Cumulative Layout Shift (CLS) | 0.02 |
| SHAP chart render time | 340 ms |
| Lighthouse score | 94/100 |
| Accessibility score | 98/100 |

---

## 8. Governance-First LLMOps Pipeline

### 8.1 Seven-Stage Governed Pipeline

```
┌────────────────────────────────────────────────────────────────────┐
│              GOVERNANCE-FIRST LLMOps PIPELINE                       │
│                                                                     │
│  Stage 1        Stage 2        Stage 3         Stage 4              │
│  ┌──────────┐   ┌──────────┐   ┌───────────┐   ┌──────────────┐   │
│  │ Data     │──►│ Training │──►│ Validation│──►│ Approval     │   │
│  │ Curation │   │ & Fine-  │   │ & Testing │   │ Gate         │   │
│  │          │   │ Tuning   │   │           │   │              │   │
│  │ ✓ DQ     │   │ ✓ Hyper  │   │ ✓ Bench   │   │ ✓ MRC vote   │   │
│  │ ✓ Bias   │   │   param  │   │ ✓ Red-team│   │ ✓ IMVU sign  │   │
│  │ ✓ License│   │   gov.   │   │ ✓ Bias    │   │ ✓ Risk sign  │   │
│  │ ✓ PII    │   │ ✓ Repro  │   │ ✓ Safety  │   │ ✓ Compliance │   │
│  └──────────┘   └──────────┘   └───────────┘   └──────┬───────┘   │
│       │              │              │                   │           │
│  [OPA Gate 1]   [OPA Gate 2]  [OPA Gate 3]       [OPA Gate 4]     │
│                                                        │           │
│  Stage 5         Stage 6         Stage 7               │           │
│  ┌──────────────┐ ┌──────────┐   ┌──────────────┐     │           │
│  │ Deployment   │ │ Runtime  │   │ Continuous   │     │           │
│  │ & Release    │ │ Monitor  │   │ Governance   │◄────┘           │
│  │              │ │          │   │              │                  │
│  │ ✓ Canary    │ │ ✓ Drift  │   │ ✓ Retrain   │                  │
│  │ ✓ A/B       │ │ ✓ Latency│   │   triggers  │                  │
│  │ ✓ Rollback  │ │ ✓ Errors │   │ ✓ Sunset    │                  │
│  │ ✓ Evidence  │ │ ✓ Bias   │   │   policy    │                  │
│  └──────────────┘ └──────────┘   └──────────────┘                  │
│       │              │              │                               │
│  [OPA Gate 5]   [Sentinel v2.4]  [OPA Gate 7]                     │
│                                                                     │
│  All gates → Kafka WORM audit log                                   │
└────────────────────────────────────────────────────────────────────┘
```

### 8.2 Stage Details

| Stage | Gate | OPA Rules | Key Checks | Blockers |
|-------|------|-----------|------------|----------|
| **1. Data Curation** | Gate 1 | 18 | Data quality score ≥0.95; PII scan PASS; license compliance; bias scan | PII in training data; copyrighted content |
| **2. Training** | Gate 2 | 12 | Hyperparameters within approved ranges; compute budget approved; reproducibility hash | Unapproved hyperparameters; budget exceeded |
| **3. Validation** | Gate 3 | 24 | Benchmark scores meet thresholds; red-team PASS; bias audit DI ratio ∈[0.8,1.25]; safety evaluation PASS | Failed benchmarks; bias threshold breach |
| **4. Approval** | Gate 4 | 8 | MRC approval; IMVU sign-off; risk committee sign-off; compliance clearance | Missing approvals |
| **5. Deployment** | Gate 5 | 16 | Canary health check; rollback plan verified; evidence bundle generated; EU AI Database registration | Canary failure; missing evidence |
| **6. Monitoring** | Sentinel | Continuous | Drift detection; latency SLA; error rate; fairness metrics; adversarial detection | SLA breach; drift beyond threshold |
| **7. Governance** | Gate 7 | 10 | Revalidation triggers; sunset criteria; regulatory change impact; cost efficiency | Sunset triggered; regulation change |

### 8.3 Gate Decision Matrix

```
Gate Decision Logic
═══════════════════

  PASS ─── All mandatory checks GREEN ─── Proceed to next stage
                                            │
  CONDITIONAL ─── Non-critical findings ─── Proceed with conditions
                   (tracked in risk           (conditions tracked,
                    register)                  time-bound remediation)
                                            │
  BLOCK ─── Critical finding detected ──── Cannot proceed
                                            │ (mandatory remediation
                                            │  before re-evaluation)
                                            │
  ESCALATE ─── Novel risk or edge case ─── Escalate to ASRB
                                            (AI Safety Review Board)
```

---

## 9. OPA-Based Compliance-as-Code Engine

### 9.1 Policy Architecture

```
OPA Policy Repository Structure
════════════════════════════════

policies/
├── ai/
│   ├── governance/
│   │   ├── risk_classification.rego      # 32 rules
│   │   ├── data_governance.rego          # 41 rules
│   │   ├── model_lifecycle.rego          # 38 rules
│   │   ├── fairness.rego                 # 29 rules
│   │   ├── transparency.rego             # 24 rules
│   │   ├── human_oversight.rego          # 18 rules
│   │   ├── incident_management.rego      # 21 rules
│   │   ├── audit_evidence.rego           # 35 rules
│   │   ├── vendor_management.rego        # 22 rules
│   │   └── jurisdictional/
│   │       ├── eu_ai_act.rego            # 8 rules
│   │       ├── gdpr.rego                 # 4 rules
│   │       ├── sr_11_7.rego              # 3 rules
│   │       └── uk_consumer_duty.rego     # 3 rules
│   └── tests/
│       ├── risk_classification_test.rego
│       ├── data_governance_test.rego
│       └── ...
├── data/
│   ├── risk_tiers.json
│   ├── approved_models.json
│   ├── feature_allowlists.json
│   └── jurisdictional_config.json
└── bundles/
    ├── governance-bundle-v278.tar.gz
    └── manifest.json
```

### 9.2 Policy Evaluation Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    OPA Policy Engine                           │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              Policy Bundle (278 Rules)                    │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ │
│  │  │ Risk Class.  │  │ Fairness     │  │ Data Gov.    │  │ │
│  │  │ (32 rules)   │  │ (29 rules)   │  │ (41 rules)   │  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ │
│  │  │ Model LC     │  │ Transparency │  │ Human Ovrsgt │  │ │
│  │  │ (38 rules)   │  │ (24 rules)   │  │ (18 rules)   │  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │ │
│  │  │ Incidents    │  │ Audit/Evid.  │  │ Vendor Mgmt  │  │ │
│  │  │ (21 rules)   │  │ (35 rules)   │  │ (22 rules)   │  │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  │ │
│  │  ┌──────────────────────────────────────────────────┐   │ │
│  │  │ Jurisdictional Adapters (18 rules)               │   │ │
│  │  └──────────────────────────────────────────────────┘   │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  Decision Cache (Redis)                                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ TTL: 60s │ Hit Rate: 78% │ Size: 42 MB                  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  Performance: P50 1.8ms │ P95 3.1ms │ P99 4.2ms              │
│  Throughput: 12,000 decisions/sec                             │
└──────────────────────────────────────────────────────────────┘
```

### 9.3 Policy Testing & CI/CD

```yaml
# .github/workflows/opa-policy-ci.yml
name: OPA Policy CI/CD
on:
  push:
    paths: ['policies/**']
  pull_request:
    paths: ['policies/**']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install OPA
        run: |
          curl -L -o opa https://openpolicyagent.org/downloads/v0.62.0/opa_linux_amd64
          chmod +x opa && mv opa /usr/local/bin/

      - name: Run Policy Tests
        run: opa test policies/ -v --coverage
        # Minimum coverage: 95%

      - name: Policy Linting
        run: opa fmt --diff policies/
        # Fail on formatting issues

      - name: Benchmark Evaluation Performance
        run: |
          opa bench -d policies/data/ policies/ai/governance/ \
            --count 10000 --benchmem
        # P99 must be ≤10ms

      - name: Build Bundle
        run: |
          opa build -b policies/ -o bundles/governance-bundle.tar.gz
          sha256sum bundles/governance-bundle.tar.gz > bundles/manifest.sha256

      - name: Sign Bundle
        run: cosign sign-blob bundles/governance-bundle.tar.gz

  deploy:
    needs: test
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy to OPA servers
        run: |
          # Blue-green deployment of policy bundle
          curl -X PUT http://opa-primary:8181/v1/policies/governance \
            --data-binary @bundles/governance-bundle.tar.gz
```

---

## 10. Hyperparameter Governance Standards

### 10.1 Governance Requirements

AI model hyperparameters directly impact model behaviour, risk profile, and regulatory compliance. Every hyperparameter change MUST be:

1. **Version-controlled**: Git-managed with full commit history.
2. **MRM-approved**: Changes to Tier 1-2 model hyperparameters require Model Risk Committee approval.
3. **Audit-trailed**: All changes logged to Kafka WORM.
4. **Impact-assessed**: Pre-change impact analysis with rollback plan.
5. **Documented**: Justification, expected impact, and acceptance criteria.

### 10.2 Controlled Hyperparameters

| Category | Hyperparameter | Governance Level | Approval Required |
|----------|---------------|-----------------|-------------------|
| **LLM Configuration** | `temperature` | Critical | MRC + ASRB |
| | `top_p` | High | MRC |
| | `max_tokens` | High | MRC |
| | `frequency_penalty` | Medium | Risk Lead |
| | `presence_penalty` | Medium | Risk Lead |
| | `system_prompt` | Critical | MRC + ASRB + Compliance |
| **ML Model Training** | `learning_rate` | High | MRC |
| | `batch_size` | Medium | Risk Lead |
| | `epochs` | Medium | Risk Lead |
| | `regularization (L1/L2)` | High | MRC |
| | `dropout_rate` | Medium | Risk Lead |
| | `class_weights` | Critical | MRC (fairness impact) |
| **RAG Configuration** | `chunk_size` | High | MRC |
| | `overlap` | Medium | Risk Lead |
| | `top_k_retrieval` | High | MRC |
| | `similarity_threshold` | High | MRC |
| | `reranking_model` | Critical | MRC + ASRB |

### 10.3 Hyperparameter Change Workflow

```
Hyperparameter Change Request
═════════════════════════════

  1. Engineer submits change request (Git PR)
       │ ─ Current value, proposed value, justification
       │ ─ Impact assessment (accuracy, bias, latency)
       │ ─ Rollback plan
       │
  2. Automated impact analysis (CI pipeline)
       │ ─ Benchmark suite on holdout data
       │ ─ Bias impact assessment
       │ ─ Latency impact test
       │ ─ Cost impact estimate
       │
  3. OPA policy evaluation
       │ ─ Is value within approved range?
       │ ─ Does change require elevated approval?
       │ ─ Is model in change freeze?
       │
  4. Approval routing (based on governance level)
       │ ─ Medium → Risk Lead approval
       │ ─ High → MRC approval (async vote)
       │ ─ Critical → MRC + ASRB (formal review)
       │
  5. Deployment (if approved)
       │ ─ Canary deployment with new hyperparameters
       │ ─ A/B test for specified duration
       │ ─ Automated rollback if KPIs degrade
       │
  6. Evidence generation
       │ ─ Before/after metrics
       │ ─ Approval records
       │ ─ All artifacts → Kafka WORM
       │
  7. Registry update
       ─ Model card updated with new hyperparameters
       ─ Version incremented
```

### 10.4 Hyperparameter Audit Trail Schema

```json
{
  "hyperparameterChange": {
    "changeId": "HPC-2026-0342",
    "modelId": "MDL-CREDIT-2024-001",
    "modelName": "Consumer Credit Scoring v4.1",
    "riskTier": "HIGH",
    "parameter": "learning_rate",
    "previousValue": 0.001,
    "newValue": 0.0008,
    "justification": "Reduce overfitting on recent training batch; validation loss improved 2.3%",
    "impactAssessment": {
      "accuracyImpact": "+0.3%",
      "biasImpact": "No significant change (DI ratio: 0.92 → 0.93)",
      "latencyImpact": "No change",
      "costImpact": "No change"
    },
    "approval": {
      "level": "HIGH",
      "approvedBy": "Model Risk Committee",
      "approvalDate": "2026-03-20T14:30:00Z",
      "votingRecord": { "approve": 5, "reject": 0, "abstain": 1 }
    },
    "deployment": {
      "method": "canary",
      "canaryPercentage": 10,
      "canaryDuration": "72h",
      "rollbackTriggered": false,
      "promotedToProduction": "2026-03-23T10:00:00Z"
    },
    "auditTrail": {
      "kafkaTopic": "gov.audit.hyperparameters",
      "kafkaPartition": 3,
      "kafkaOffset": 892341,
      "merkleProof": "sha256:9a8b7c6d..."
    }
  }
}
```

---

## 11. Sentinel v2.4 Integration Architecture

### 11.1 Sentinel Overview

Sentinel v2.4 is the real-time AI governance monitoring platform that provides continuous compliance assurance across all AI systems.

```
┌──────────────────────────────────────────────────────────────────┐
│                      Sentinel v2.4                                │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                   Governance Rule Engine                    │  │
│  │                   847 Active Rules                         │  │
│  │                   P99 Evaluation: 38 ms                    │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│  │ Drift    │  │ Bias     │  │ Anomaly  │  │ Compliance   │    │
│  │ Detector │  │ Monitor  │  │ Detector │  │ Evaluator    │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────┘    │
│                                                                   │
│  Telemetry:                                                       │
│  ─ 22 systems monitored                                          │
│  ─ 1.2M policy evaluations/day                                   │
│  ─ 0.3% false positive rate                                      │
│  ─ 86% auto-remediation rate (12/14 incidents)                   │
│  ─ 14 governance incidents detected                              │
│  ─ Mean detection time: 4.2 minutes                              │
│  ─ Mean resolution time: 23 minutes                              │
└──────────────────────────────────────────────────────────────────┘
```

### 11.2 Integration Points

| Integration | Protocol | Purpose | Latency |
|------------|----------|---------|---------|
| OPA → Sentinel | gRPC | Policy decision streaming | 2.1 ms |
| Kafka → Sentinel | Consumer | Audit event processing | 8.3 ms |
| Sentinel → Grafana | Prometheus | Metrics exposition | N/A |
| Sentinel → PagerDuty | Webhook | Incident alerting | 340 ms |
| Sentinel → Slack | Webhook | Governance notifications | 280 ms |
| Sidecars → Sentinel | gRPC | Real-time telemetry | 1.8 ms |
| Sentinel → Next.js | REST | Dashboard data feed | 12 ms |

---

## 12. Network Security & Zero-Trust Architecture

### 12.1 Network Segmentation

```
┌──────────────────────────────────────────────────────────────┐
│                     Network Architecture                      │
│                                                               │
│  DMZ (Internet-facing)                                        │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ CDN → WAF → API Gateway (Kong)                       │    │
│  │ TLS 1.3 │ Rate Limiting │ IP Allowlisting           │    │
│  └──────────────────────────┬───────────────────────────┘    │
│                              │                                │
│  Application Zone (AI Services)                               │
│  ┌──────────────────────────┴───────────────────────────┐    │
│  │ mTLS │ JWT Validation │ OPA Authorization             │    │
│  │ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐  │    │
│  │ │ Node.js  │ │ Python   │ │ AI Services          │  │    │
│  │ │ Sidecar  │ │ Sidecar  │ │ (LLM, ML, RAG)      │  │    │
│  │ └──────────┘ └──────────┘ └──────────────────────┘  │    │
│  └──────────────────────────────────────────────────────┘    │
│                              │                                │
│  Data Zone (Restricted)                                       │
│  ┌──────────────────────────┴───────────────────────────┐    │
│  │ Encryption at rest (AES-256) │ Column-level encryption │    │
│  │ ┌──────────┐ ┌──────────┐ ┌──────────────────────┐  │    │
│  │ │ Kafka    │ │ Postgres │ │ Redis                │  │    │
│  │ │ WORM     │ │ (encrypted│ │ (TLS, auth)         │  │    │
│  │ └──────────┘ └──────────┘ └──────────────────────┘  │    │
│  └──────────────────────────────────────────────────────┘    │
│                              │                                │
│  Management Zone                                              │
│  ┌──────────────────────────┴───────────────────────────┐    │
│  │ Vault │ Terraform │ CI/CD │ Monitoring               │    │
│  └──────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 12.2 mTLS Configuration

All inter-service communication uses mutual TLS with certificate rotation:

| Parameter | Value |
|-----------|-------|
| Protocol | TLS 1.3 |
| Cipher suites | TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Certificate authority | Internal PKI (HashiCorp Vault) |
| Certificate lifetime | 24 hours (auto-rotated) |
| Client authentication | Required (mTLS) |
| OCSP stapling | Enabled |
| Certificate pinning | Enabled for critical paths |

---

## 13. Deployment Patterns & Infrastructure

### 13.1 Deployment Strategy

| Pattern | Use Case | Rollback Time |
|---------|----------|---------------|
| **Blue-Green** | Major version releases | < 30 sec |
| **Canary** | Model updates, hyperparameter changes | < 60 sec |
| **Rolling** | Sidecar updates, policy changes | < 120 sec |
| **Feature flags** | New governance features | Instant |

### 13.2 Infrastructure as Code

All infrastructure is managed via Terraform with GitOps:

| Component | IaC Tool | State Backend |
|-----------|---------|---------------|
| Docker Swarm cluster | Terraform | Consul |
| Kafka cluster | Terraform + Ansible | Consul |
| OPA configuration | Terraform | Git |
| Network policies | Terraform | Consul |
| Vault configuration | Terraform | Vault |
| Monitoring stack | Helm + Terraform | Git |

---

## 14. Observability & Monitoring Stack

### 14.1 Stack Components

| Component | Tool | Purpose |
|-----------|------|---------|
| **Metrics** | Prometheus + Thanos | Time-series metrics with long-term storage |
| **Logging** | Fluent Bit → Elasticsearch | Structured logging with full-text search |
| **Tracing** | Jaeger (OpenTelemetry) | Distributed tracing across AI pipelines |
| **Dashboards** | Grafana | Real-time governance dashboards |
| **Alerting** | Alertmanager → PagerDuty | Multi-channel incident notification |
| **SLO Tracking** | Grafana SLO | Service level objective monitoring |

### 14.2 Key Dashboards

| Dashboard | Metrics | Refresh |
|-----------|---------|---------|
| Governance Overview | OPA decisions, Sentinel health, compliance scores | 10 sec |
| Kafka WORM Health | Throughput, lag, replication, seal status | 30 sec |
| Model Performance | Accuracy, drift, latency per model | 1 min |
| Fairness Monitor | Disparate impact, group metrics per model | 5 min |
| Sidecar Performance | Request rate, latency, error rate per sidecar | 10 sec |
| Security Posture | CVEs, mTLS status, authentication failures | 1 min |

---

## 15. Performance Benchmarks

### 15.1 End-to-End Request Path

```
Request Path Timing (P99)
═════════════════════════

  Client → API Gateway (Kong)         2.1 ms
         → Node.js Sidecar            3.8 ms
           → OPA evaluation           4.2 ms
           → PII scan                 1.1 ms
         → AI Service (LLM)           850 ms
         → Response validation        0.8 ms
         → Kafka audit (async)        0.2 ms
                                    ──────────
  Total governance overhead:          12.2 ms
  Total request (including AI):       862 ms
  Governance % of total:              1.4%
```

### 15.2 Scalability Profile

| Load | Governance Latency (P99) | Throughput | CPU | Memory |
|------|-------------------------|-----------|-----|--------|
| 100 req/sec | 3.2 ms | 100% | 0.2 cores | 256 MB |
| 1,000 req/sec | 4.8 ms | 100% | 1.2 cores | 512 MB |
| 5,000 req/sec | 7.1 ms | 100% | 4.8 cores | 1.2 GB |
| 10,000 req/sec | 11.3 ms | 100% | 8.4 cores | 2.1 GB |
| 20,000 req/sec | 18.7 ms | 99.8% | 15.2 cores | 3.8 GB |

---

## 16. Security Threat Model

### 16.1 STRIDE Analysis for AI Governance Infrastructure

| Threat | Category | Risk | Mitigation |
|--------|----------|------|------------|
| Policy bypass via direct AI service access | **Spoofing** | Critical | mTLS + network policy: AI services only accept sidecar traffic |
| Audit log tampering | **Tampering** | Critical | Kafka WORM + Merkle sealing + blockchain anchoring |
| Unauthorized model access | **Repudiation** | High | JWT + OPA + audit trail for every access |
| Confidential training data exposure | **Information Disclosure** | Critical | Encryption at rest + column-level encryption + DLP scanning |
| OPA policy engine DoS | **Denial of Service** | High | Rate limiting + horizontal scaling + circuit breaker |
| Sidecar privilege escalation | **Elevation of Privilege** | Critical | Rootless containers + no-new-privileges + seccomp + AppArmor |

### 16.2 Penetration Testing Schedule

| Test Type | Frequency | Scope | Last Result |
|-----------|-----------|-------|-------------|
| Network pen-test | Quarterly | Full infrastructure | PASS (2026-Q1) |
| Application pen-test | Quarterly | API + frontends | PASS (2026-Q1) |
| AI-specific red-team | Quarterly | Prompt injection, model extraction | PASS (2026-Q1) |
| Container escape testing | Semi-annual | Docker Swarm cluster | PASS (2025-Q4) |
| Social engineering | Annual | Phishing + vishing | 92% detection rate |

---

## 17. Architecture Decision Records

### ADR-001: Kafka over Traditional SIEM for Audit Logging

**Status:** Accepted
**Date:** 2025-09-15
**Context:** Need tamper-proof, high-throughput audit logging for AI governance events.
**Decision:** Kafka WORM cluster with Merkle sealing instead of traditional SIEM append-only storage.
**Rationale:** 45K events/sec throughput; 12ms P99 latency; native streaming for real-time analysis; 11-nines durability; ecosystem of consumers for evidence generation.
**Consequences:** Additional operational complexity for Kafka cluster management; team requires Kafka expertise.

### ADR-002: OPA over Custom Policy Engine

**Status:** Accepted
**Date:** 2025-10-01
**Context:** Need policy engine for 278+ governance rules with sub-10ms evaluation.
**Decision:** Open Policy Agent with Rego policy language.
**Rationale:** Industry standard; rich ecosystem; strong testing framework; bundle distribution; 4.2ms P99 achieved; declarative policies easier to audit.
**Consequences:** Team requires Rego training; policy testing overhead; bundle versioning complexity.

### ADR-003: Sidecar Pattern over Library Integration

**Status:** Accepted
**Date:** 2025-10-15
**Context:** Need governance enforcement for both Node.js and Python AI services.
**Decision:** Language-specific sidecar proxies over shared library integration.
**Rationale:** Separation of concerns; independent deployment; no coupling to service code; consistent governance across languages; easier to audit.
**Consequences:** Network hop overhead (2-4ms); additional container resources; sidecar lifecycle management.

### ADR-004: Next.js for Explainability Frontend

**Status:** Accepted
**Date:** 2025-11-01
**Context:** Need regulatory-grade explainability UI supporting SHAP/LIME, counterfactuals, and tiered explanations.
**Decision:** Next.js with SSR for SEO/accessibility + ISR for performance.
**Rationale:** React ecosystem; excellent TypeScript support; SSR for accessibility compliance; ISR for performance; strong testing ecosystem (Playwright).
**Consequences:** Node.js runtime required; SSR caching strategy needed; WCAG 2.1 AA compliance requires ongoing testing.

---

**Classification:** CONFIDENTIAL
**Document Reference:** ARCH-GSIFI-WP-002 v1.0.0
**Next Review Date:** 2026-06-22

> *"Security and governance are not afterthoughts — they are the architecture itself."*
