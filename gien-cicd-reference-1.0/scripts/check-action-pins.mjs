import { readFile, readdir } from "node:fs/promises";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nestedWorkflowDir = join(projectRoot, ".github", "workflows");
const workflowPaths = (await readdir(nestedWorkflowDir, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
  .map((entry) => join(nestedWorkflowDir, entry.name));

const gitRootResult = spawnSync("git", ["rev-parse", "--show-toplevel"], { cwd: projectRoot, encoding: "utf8" });
if (gitRootResult.status === 0) {
  const repoWorkflowDir = join(gitRootResult.stdout.trim(), ".github", "workflows");
  try {
    const rootWorkflows = await readdir(repoWorkflowDir, { withFileTypes: true });
    workflowPaths.push(...rootWorkflows
      .filter((entry) => entry.isFile() && /\.ya?ml$/i.test(entry.name))
      .map((entry) => join(repoWorkflowDir, entry.name)));
  } catch { /* Standalone checkout or repository has no root workflows. */ }
}

// GitHub Actions step syntax uses "- uses:", while reusable workflows use "uses:".
// Match both forms; checking only the latter silently misses normal action steps.
export function extractUses(content) {
  const refs = [];
  for (const [index, line] of content.split(/\r?\n/).entries()) {
    const match = line.match(/^\s*(?:-\s*)?uses:\s*([^\s#]+)/);
    if (match) refs.push({ line: index + 1, reference: match[1] });
  }
  return refs;
}

export function findUnpinnedUses(content) {
  return extractUses(content).filter(({ reference }) => {
    if (reference.startsWith("./")) return false;
    const at = reference.lastIndexOf("@");
    const revision = at >= 0 ? reference.slice(at + 1) : "";
    return !/^[a-f0-9]{40}$/.test(revision);
  });
}

const failures = [];
let checked = 0;
for (const path of [...new Set(workflowPaths)]) {
  const content = await readFile(path, "utf8");
  checked += extractUses(content).length;
  for (const issue of findUnpinnedUses(content)) failures.push(`${path}:${issue.line}: ${issue.reference}`);
}
if (failures.length) {
  console.error("Non-immutable GitHub Action/reusable-workflow references:");
  for (const failure of failures) console.error(` - ${failure}`);
  process.exit(1);
}
console.log(`PASS: ${new Set(workflowPaths).size} workflow file(s), ${checked} external uses: reference(s); all pinned to full 40-character SHAs.`);
