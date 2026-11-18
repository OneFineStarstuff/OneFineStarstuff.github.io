import test from "node:test";
import assert from "node:assert/strict";
import { extractUses, findUnpinnedUses } from "../scripts/check-action-pins.mjs";

test("action pin checker recognizes list-item step syntax", () => {
  const source = "steps:\n  - name: checkout\n    uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
  assert.equal(extractUses(source).length, 1);
  assert.deepEqual(findUnpinnedUses(source), []);
});

test("action pin checker recognizes reusable workflow syntax", () => {
  const source = "jobs:\n  verify:\n    uses: org/repo/.github/workflows/verify.yml@bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
  assert.equal(extractUses(source).length, 1);
  assert.deepEqual(findUnpinnedUses(source), []);
});

test("action pin checker rejects mutable action tags in list-item syntax", () => {
  const source = "steps:\n  - uses: actions/setup-node@v4\n";
  assert.deepEqual(findUnpinnedUses(source), [{ line: 2, reference: "actions/setup-node@v4" }]);
});

test("action pin checker ignores local composite actions", () => {
  const source = "steps:\n  - uses: ./.github/actions/local\n";
  assert.deepEqual(findUnpinnedUses(source), []);
});
