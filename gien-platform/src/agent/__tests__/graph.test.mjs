import test from "node:test";
import assert from "node:assert/strict";
import { validateEvidenceGraph } from "../graph.ts";

const validGraph = () => ({
  graphId: "GRAPH-001",
  schemaVersion: "1.0.0",
  nodes: [
    { id: "SRC-001", kind: "SOURCE_OBSERVATION", label: "GitHub commit", evidenceStatus: "VERIFIED" },
    { id: "CLM-001", kind: "CLAIM", label: "Commit passed CI" }
  ],
  edges: [
    { from: "CLM-001", to: "SRC-001", relation: "DERIVED_FROM" }
  ]
});

test("accepts a graph with valid nodes and evidence lineage", () => {
  assert.deepEqual(validateEvidenceGraph(validGraph()), []);
});

test("rejects dangling graph edges", () => {
  const graph = validGraph();
  graph.edges.push({ from: "CLM-001", to: "MISSING", relation: "REFERENCES" });
  assert.ok(validateEvidenceGraph(graph).some(issue => issue.includes("dangling")));
});

test("rejects dependency cycles", () => {
  const graph = validGraph();
  graph.edges.push(
    { from: "CLM-001", to: "SRC-001", relation: "DEPENDS_ON" },
    { from: "SRC-001", to: "CLM-001", relation: "DEPENDS_ON" }
  );
  assert.ok(validateEvidenceGraph(graph).some(issue => issue.includes("acyclic")));
});

test("rejects duplicate node identifiers", () => {
  const graph = validGraph();
  graph.nodes.push({ id: "SRC-001", kind: "ARTIFACT", label: "Duplicate" });
  assert.ok(validateEvidenceGraph(graph).some(issue => issue.includes("duplicate")));
});
