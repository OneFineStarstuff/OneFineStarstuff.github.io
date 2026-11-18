export type EvidenceNodeKind =
  | "SOURCE_OBSERVATION"
  | "ARTIFACT"
  | "COMMIT"
  | "WORKFLOW_RUN"
  | "DEPLOYMENT"
  | "CLAIM"
  | "CONTROL"
  | "METRIC"
  | "RISK"
  | "DECISION"
  | "REMEDIATION";

export type EvidenceRelation =
  | "PRODUCED_BY"
  | "REFERENCES"
  | "VALIDATES"
  | "CONTRADICTS"
  | "SUPERSEDES"
  | "DEPENDS_ON"
  | "AFFECTS"
  | "DERIVED_FROM"
  | "IMPLEMENTS"
  | "ATTESTS_TO";

export interface EvidenceGraphNode {
  id: string;
  kind: EvidenceNodeKind;
  label: string;
  evidenceStatus?: "VERIFIED" | "REPORTED" | "SIMULATED" | "INFERRED" | "CONFLICTED" | "UNAVAILABLE";
  sourceUri?: string;
}

export interface EvidenceGraphEdge {
  from: string;
  to: string;
  relation: EvidenceRelation;
}

export interface EvidenceGraph {
  graphId: string;
  schemaVersion: string;
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
}

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

const NODE_KINDS: readonly string[] = [
  "SOURCE_OBSERVATION", "ARTIFACT", "COMMIT", "WORKFLOW_RUN", "DEPLOYMENT",
  "CLAIM", "CONTROL", "METRIC", "RISK", "DECISION", "REMEDIATION"
];

const RELATIONS: readonly string[] = [
  "PRODUCED_BY", "REFERENCES", "VALIDATES", "CONTRADICTS", "SUPERSEDES",
  "DEPENDS_ON", "AFFECTS", "DERIVED_FROM", "IMPLEMENTS", "ATTESTS_TO"
];

function findDependencyCycle(nodes: readonly EvidenceGraphNode[], edges: readonly EvidenceGraphEdge[]): boolean {
  const adjacency = new Map<string, string[]>();
  for (const node of nodes) adjacency.set(node.id, []);
  for (const edge of edges) {
    if (edge.relation === "DEPENDS_ON" && adjacency.has(edge.from)) {
      adjacency.get(edge.from)?.push(edge.to);
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (id: string): boolean => {
    if (visiting.has(id)) return true;
    if (visited.has(id)) return false;
    visiting.add(id);
    for (const next of adjacency.get(id) ?? []) {
      if (visit(next)) return true;
    }
    visiting.delete(id);
    visited.add(id);
    return false;
  };

  for (const node of nodes) {
    if (visit(node.id)) return true;
  }
  return false;
}

export function validateEvidenceGraph(input: unknown): string[] {
  const issues: string[] = [];
  if (!isRecord(input)) return ["evidence graph must be an object"];
  if (!nonEmpty(input.graphId)) issues.push("graphId is required");
  if (typeof input.schemaVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(input.schemaVersion)) {
    issues.push("schemaVersion must be semantic version");
  }
  if (!Array.isArray(input.nodes)) issues.push("nodes must be an array");
  if (!Array.isArray(input.edges)) issues.push("edges must be an array");
  if (!Array.isArray(input.nodes) || !Array.isArray(input.edges)) return issues;

  const ids = new Set<string>();
  const nodes: EvidenceGraphNode[] = [];
  for (const item of input.nodes) {
    if (!isRecord(item)) {
      issues.push("every graph node must be an object");
      continue;
    }
    if (!nonEmpty(item.id)) {
      issues.push("every graph node requires an id");
      continue;
    }
    if (ids.has(item.id)) issues.push("duplicate graph node id: " + item.id);
    ids.add(item.id);
    if (!NODE_KINDS.includes(String(item.kind))) issues.push("invalid graph node kind for " + item.id);
    if (!nonEmpty(item.label)) issues.push("graph node label is required for " + item.id);
    nodes.push(item as unknown as EvidenceGraphNode);
  }

  const edges: EvidenceGraphEdge[] = [];
  for (const item of input.edges) {
    if (!isRecord(item)) {
      issues.push("every graph edge must be an object");
      continue;
    }
    if (!nonEmpty(item.from) || !nonEmpty(item.to)) {
      issues.push("graph edge requires from and to identifiers");
      continue;
    }
    if (!RELATIONS.includes(String(item.relation))) {
      issues.push("invalid graph edge relation");
      continue;
    }
    if (item.from === item.to) issues.push("self-referential graph edges are prohibited");
    if (!ids.has(item.from)) issues.push("dangling graph edge source: " + item.from);
    if (!ids.has(item.to)) issues.push("dangling graph edge target: " + item.to);
    edges.push(item as unknown as EvidenceGraphEdge);
  }

  if (findDependencyCycle(nodes, edges)) {
    issues.push("DEPENDS_ON relationships must be acyclic");
  }

  return issues;
}
