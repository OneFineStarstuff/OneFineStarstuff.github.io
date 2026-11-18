// RFC 6962-style domain-separated Merkle tree hashing using SHA-256.
import { createHash } from "node:crypto";
function sha256(bytes: Uint8Array): Uint8Array { return new Uint8Array(createHash("sha256").update(bytes).digest()); }
function concat(left: Uint8Array, right: Uint8Array): Uint8Array { const out = new Uint8Array(left.length + right.length); out.set(left, 0); out.set(right, left.length); return out; }
function hex(bytes: Uint8Array): string { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function largestPowerOfTwoLessThan(n: number): number { let k = 1; while (k * 2 < n) k *= 2; return k; }
export function merkleRootFromLeaves(leaves: Uint8Array[]): string {
  if (leaves.length === 0) return hex(sha256(new Uint8Array()));
  const treeHash = (items: Uint8Array[]): Uint8Array => {
    if (items.length === 1) return sha256(concat(new Uint8Array([0]), items[0]));
    const split = largestPowerOfTwoLessThan(items.length);
    return sha256(concat(treeHash(items.slice(0, split)), treeHash(items.slice(split))));
  };
  return hex(treeHash(leaves));
}
export function merkleRootFromEntries(entries: Array<{ path: string; size: number; sha256: string }>): string {
  const sorted = [...entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const leaves = sorted.map((entry) => new TextEncoder().encode(JSON.stringify({ path: entry.path.normalize("NFC"), size: entry.size, sha256: entry.sha256 })));
  return merkleRootFromLeaves(leaves);
}
