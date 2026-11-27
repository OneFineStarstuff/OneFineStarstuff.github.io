import test from "node:test";
import assert from "node:assert/strict";
import { merkleRootFromLeaves, merkleRootFromEntries } from "../src/evidence/merkle.ts";
test("empty Merkle tree has deterministic SHA-256 empty root", () => { assert.equal(merkleRootFromLeaves([]), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); });
test("RFC6962-style tree root is deterministic and input-order independent for entry records", () => { const a = [{ path: "a.txt", size: 1, sha256: "0".repeat(64) }, { path: "b.txt", size: 2, sha256: "1".repeat(64) }]; assert.equal(merkleRootFromEntries(a), merkleRootFromEntries([...a].reverse())); });
test("different evidence changes root", () => { const a = merkleRootFromEntries([{ path: "a", size: 1, sha256: "0".repeat(64) }]); const b = merkleRootFromEntries([{ path: "a", size: 2, sha256: "0".repeat(64) }]); assert.notEqual(a, b); });
