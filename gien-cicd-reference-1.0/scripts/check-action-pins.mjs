import { readFile, readdir } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nestedWorkflowDir = join(projectRoot, ".github", "workflows");
const workflowPaths = (await readdir(nestedWorkflowDir, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && entry.name.endsWith(".yml"))
  .map((entry) => join(nestedWorkflowDir, entry.name));

const gitRootResult = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: projectRoot, encoding: "utf8" });
if (gitRootResult.status === 0) {
  const repoWorkflowDir = join(gitRootResult.stdout.trim(), ".github", "workflows");
  for (const name of ["gien-cicd-reference-ci.yml", "gien-cicd-reference-release.yml"]) {
    const path = join(repoWorkflowDir, name);
    try { await readFile(path, "utf8"); workflowPaths.push(path); } catch { /* Not installed in a standalone package checkout. */ }
  }
}

const failures = [];
for (const path of workflowPaths) {
  const content = await readFile(path, "utf8");
  for (const [index, line] of content.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*uses:\s*([^\s#]+)/);
    if (!match) continue;
    const ref = match[1];
    if (ref.startsWith("./")) continue;
    const at = ref.lastIndexOf("@");
    const revision = at >= 0 ? ref.slice(at + 1) : "";
    if (!/^[a-f0-9]{40}$/.test(revision)) failures.push(`${path}:${index + 1}: ${ref}`);
  }
}
if (failures.length) {
  console.error("Non-immutable GitHub Action/reusable-workflow references:");
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}
console.log(`PASS: ${workflowPaths.length} workflow file(s); all external uses: references are pinned to full 40-character SHAs.`);
