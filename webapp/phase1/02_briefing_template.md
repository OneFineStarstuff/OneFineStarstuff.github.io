# 02 — Daily Briefing Template

## Structure (mandatory three-tag format)

Every daily supervisory briefing is generated in exactly three top-level tags:

```
<title>    — document id (GIEN-DOSSIER-YYYY-DDD), edition name, evaluation window, edition date
<abstract> — 5–7 ranked takeaways, most material first; each a single self-contained sentence
<content>  — the full dossier body (section contract below)
```

## Section contract for \<content>

| Section | Required | Contents |
| --- | --- | --- |
| Delivery verification | yes | All channels: repository (PR + merge sha), Drive export pair, closing summary, duplicate check |
| Sealed baselines | yes | The 12-index table with values, 24h deltas, bands, and notes |
| Control domain status | yes | Domains 01–10 with GREEN/AMBER/RED and consecutive-window counts |
| Drills & replays | yes | Scenario register, freeze-vote/dry-run/live statuses, replay determinism results |
| Cryptographic evidence | yes | Merkle root, artifacts sealed, ledger gaps, PQC/zk/TEE health |
| Strategic pathways | yes | Per-audience recommendations (G-SIFIs, JSTs, clearinghouses, secretariats, engineers) |
| Next window outlook | yes | Next dossier id, edition, expected drills |
| Footer | yes | Knowledge citations where applicable + the fictional-simulation disclaimer |

## Generation rules

1. **Never fabricate an unobserved window.** A briefing exists only for a window that has closed (09:00 UTC); racing duplicate dispatches re-present the sealed window and create no new artifacts.
2. **Values come from the sealed window.** Any number in the briefing must complete the evidence chain (see 01_evidence_model.md).
3. **Windows are sealed before generation.** The Merkle root over the window's artifacts is computed before the briefing text is written; the briefing records that root.
4. **One dossier per window**, across all channels; duplicates are defects.

## Labelling standard (every surface)

- Every document, page, and export carries the italic fictional-simulation disclaimer: indices, drills, filings, signatures, and Merkle roots are simulated data and do not describe real systems.
- Real-framework content is labelled informational and not legal advice, with citation links to primary or authoritative secondary sources.
- The treaty layer (Interstellar AI Governance Accord, Galactic Treaty Framework, CFE-1.0, Protocol SGR-028, GIEN Phase VI-δ/VII/Ω-GAR) is always presented as the fictional layer.

## Delivery channels (per window)

Repository (branch → PR → squash merge, sequential WP numbering) · Google Drive export pair (DOCX + PDF) · Notion closing summary · knowledge baseline bullet. The static briefing page is generated from the same sealed values and is immutable history.
