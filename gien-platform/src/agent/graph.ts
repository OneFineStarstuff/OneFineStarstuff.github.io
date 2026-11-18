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

const MAX_GRAPH_NODES = 10_000;
const MAX_GRAPH_EDGES = 50_000;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isHttpsUri(value: unknown): value is string {
  if (!nonEmpty(value)) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

const NODE_KINDS: readonly string[] = [
  "SOURCE_OBSERVATION", "ARTIFACT", "COMMIT", "WORKFLOW_RUN", "DEPLOYMENT",
  "CLAIM", "CONTROL", "METRIC", "RISK", "DECISION", "REMEDIATION"
];

const EVIDENCE_STATUSES: readonly string[] = [
  "VERIFIED", "REPORTED", "SIMULATED", "INFERRED", "CONFLICTED", "UNAVAILABLE"
];

const RELATIONS: readonly string[] = [
  "PRODUCED_BY", "REFERENCES", "VALIDATES", "CONTRADICTS", "SUPERSEDES",
  "DEPENDS_ON", "AFFECTS", "DERIVED_FROM", "IMPLEMENTS", "ATTESTS_TO"
];

function findDependencyCycle(nodes: readonly EvidenceGraphNode[], edges: readonly EvidenceGraphEdge[]): boolean {
  const adjacency = new Map<string, string[]>();
  const indegree = new Map<string, number>();

  for (const node of nodes) {
    adjacency.set(node.id, []);
    indegree.set(node.id, 0);
  }

  for (const edge of edges) {
    if (edge.relation !== "DEPENDS_ON" ||
        !adjacency.has(edge.from) ||
        !adjacency.has(edge.to)) {
      continue;
    }
    adjacency.get(edge.from)?.push(edge.to);
    indegree.set(edge.to, (indegree.get(edge.to) ?? 0) + 1);
  }

  const queue = nodes
    .filter(node => (indegree.get(node.id) ?? 0) === 0)
    .map(node => node.id);
  let visitedCount = 0;

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) continue;
    visitedCount += 1;

    for (const next of adjacency.get(current) ?? []) {
      const nextDegree = (indegree.get(next) ?? 0) - 1;
      indegree.set(next, nextDegree);
      if (nextDegree === 0) queue.push(next);
    }
  }

  return visitedCount !== nodes.length;
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

  if (input.nodes.length > MAX_GRAPH_NODES) {
    issues.push("graph node count exceeds the configured validation limit");
    return issues;
  }
  if (input.edges.length > MAX_GRAPH_EDGES) {
    issues.push("graph edge count exceeds the configured validation limit");
    return issues;
  }

  const ids = new Set<string>();
  const nodeById = new Map<string, EvidenceGraphNode>();
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
    if (item.kind === "SOURCE_OBSERVATION" && !EVIDENCE_STATUSES.includes(String(item.evidenceStatus))) {
      issues.push("source observation requires a recognized evidence status: " + item.id);
    }
    if (nonEmpty(item.sourceUri) && !isHttpsUri(item.sourceUri)) {
      issues.push("graph sourceUri must be HTTPS: " + item.id);
    }
    const node = item as unknown as EvidenceGraphNode;
    nodes.push(node);
    nodeById.set(node.id, node);
  }

  const edges: EvidenceGraphEdge[] = [];
  const claimLineage = new Set<string>();
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

    if (item.relation === "DERIVED_FROM" &&
        nodeById.get(item.from)?.kind === "CLAIM" &&
        nodeById.get(item.to)?.kind === "SOURCE_OBSERVATION") {
      claimLineage.add(item.from);
    }
    edges.push(item as unknown as EvidenceGraphEdge);
  }

  for (const node of nodes) {
    if (node.kind === "CLAIM" && !claimLineage.has(node.id)) {
      issues.push("claim node requires source observation lineage: " + node.id);
    }
  }

  if (findDependencyCycle(nodes, edges)) {
    issues.push("DEPENDS_ON relationships must be acyclic");
  }

  return issues;
}
