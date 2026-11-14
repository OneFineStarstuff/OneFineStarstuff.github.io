import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

test("evidence builder creates bundle and verifier accepts unchanged bundle, rejects tampering and unlisted content", async () => {
  const base = await mkdtemp(join(tmpdir(), "gien-evidence-test-"));
  const input = join(base, "input");
  const output = join(base, "bundle");
  const projectRoot = new URL("../", import.meta.url);
  try {
    await mkdir(input);
    await writeFile(join(input, "ci-result.json"), JSON.stringify({ conclusion: "success", fictional: true }));
    const build = spawnSync(process.execPath, ["--experimental-strip-types", "scripts/build-evidence.ts", "--input", input, "--output", output, "--deployment-id", "TEST-0001", "--source-revision", "a".repeat(40), "--image", `ghcr.io/example/api@sha256:${"b".repeat(64)}`], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(build.status, 0, build.stderr || build.stdout);
    const verify = spawnSync(process.execPath, ["--experimental-strip-types", "scripts/verify-evidence.ts", "--bundle", output], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(verify.status, 0, verify.stderr || verify.stdout);
    assert.match(verify.stdout, /LOCAL_INTEGRITY_PASS_EXTERNAL_ANCHORS_UNVERIFIED/);
    const manifest = JSON.parse(await readFile(join(output, "manifest.json"), "utf8"));
    assert.equal(manifest.evidenceCount, 2);
    const entryPath = join(output, "contents", "ci-result.json");
    const original = await readFile(entryPath, "utf8");
    await writeFile(entryPath, `${original}tampered`);
    const tampered = spawnSync(process.execPath, ["--experimental-strip-types", "scripts/verify-evidence.ts", "--bundle", output], { cwd: projectRoot, encoding: "utf8" });
    assert.notEqual(tampered.status, 0);
    await writeFile(entryPath, original);
    await writeFile(join(output, "contents", "unlisted.txt"), "unlisted");
    const extra = spawnSync(process.execPath, ["--experimental-strip-types", "scripts/verify-evidence.ts", "--bundle", output], { cwd: projectRoot, encoding: "utf8" });
    assert.notEqual(extra.status, 0);
    await rm(join(output, "contents", "unlisted.txt"));
    manifest.deployment.id = "ALTERED-DEPLOYMENT-ID";
    await writeFile(join(output, "manifest.json"), JSON.stringify(manifest));
    const metadataTamper = spawnSync(process.execPath, ["--experimental-strip-types", "scripts/verify-evidence.ts", "--bundle", output], { cwd: projectRoot, encoding: "utf8" });
    assert.notEqual(metadataTamper.status, 0);
  } finally { await rm(base, { recursive: true, force: true }); }
});
