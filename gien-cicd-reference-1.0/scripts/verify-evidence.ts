import { createHash } from "node:crypto";
import { readFile, lstat, readdir } from "node:fs/promises";
import { join, resolve, sep, relative } from "node:path";
import { canonicalJson } from "../src/evidence/canonical.ts";
import { merkleRootFromEntries } from "../src/evidence/merkle.ts";
type Entry = { path: string; size: number; sha256: string };
function arg(name: string): string { const index = process.argv.indexOf(`--${name}`); const value = index >= 0 ? process.argv[index + 1] : undefined; if (!value || value.startsWith("--")) throw new Error(`Missing --${name}`); return value; }
function hash(bytes: Uint8Array): string { return createHash("sha256").update(bytes).digest("hex"); }
async function main(): Promise<void> {
  const bundle = resolve(arg("bundle"));
  const manifest = JSON.parse(await readFile(join(bundle, "manifest.json"), "utf8"));
  if (manifest.format !== "GIEN-EVIDENCE-BUNDLE/v1" || manifest.hashAlgorithm !== "sha-256") throw new Error("Unsupported evidence manifest format.");
  if (!Array.isArray(manifest.entries)) throw new Error("Manifest entries must be an array.");
  const seen = new Set<string>();
  const checked: Entry[] = [];
  const listedOrder = (manifest.entries as Entry[]).map((entry) => entry.path);
  const sortedOrder = [...listedOrder].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (JSON.stringify(listedOrder) !== JSON.stringify(sortedOrder)) throw new Error("Manifest entries are not in canonical path order.");
  for (const entry of manifest.entries as Entry[]) {
    if (typeof entry.path !== "string" || !entry.path.startsWith("contents/") || entry.path.startsWith("/") || entry.path.normalize("NFC") !== entry.path || entry.path.split("/").some((part) => part === ".." || part === "." || part === "")) throw new Error(`Unsafe path in manifest: ${entry.path}`);
    const normalized = entry.path.split("/").join(sep);
    if (seen.has(normalized)) throw new Error(`Duplicate evidence path: ${entry.path}`);
    seen.add(normalized);
    let cursor = bundle;
    for (const part of normalized.split(sep)) { cursor = join(cursor, part); const segmentInfo = await lstat(cursor); if (segmentInfo.isSymbolicLink()) throw new Error(`Symbolic-link path is not permitted: ${entry.path}`); }
    const file = join(bundle, normalized);
    const info = await lstat(file);
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Not a regular file: ${entry.path}`);
    const bytes = await readFile(file);
    if (bytes.byteLength !== entry.size || hash(bytes) !== entry.sha256) throw new Error(`Artifact integrity failure: ${entry.path}`);
    checked.push(entry);
  }
  if (manifest.evidenceCount !== checked.length) throw new Error("Evidence count does not match manifest.");
  const expectedMetadata = { format: manifest.format, hashAlgorithm: manifest.hashAlgorithm, merkleConstruction: manifest.merkleConstruction, deployment: manifest.deployment };
  const metadataBytes = await readFile(join(bundle, "contents", "gien-bundle-metadata.json"));
  if (new TextDecoder().decode(metadataBytes) !== `${canonicalJson(expectedMetadata)}\n`) throw new Error("Manifest metadata does not match the Merkle-committed metadata leaf.");
  const actualFiles: string[] = [];
  async function collect(dir: string): Promise<void> {
    const items = await readdir(dir, { withFileTypes: true });
    for (const item of items) { const full = join(dir, item.name); const info = await lstat(full); if (info.isSymbolicLink()) throw new Error(`Unexpected symlink in bundle: ${full}`); if (info.isDirectory()) await collect(full); else if (info.isFile()) actualFiles.push(relative(bundle, full).split(sep).join("/")); else throw new Error(`Unsupported bundle entry: ${full}`); }
  }
  await collect(join(bundle, "contents"));
  actualFiles.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  const expectedFiles = [...seen].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) throw new Error("Bundle file inventory differs from manifest (missing or unlisted file).");
  const computed = merkleRootFromEntries(checked);
  const rootFile = (await readFile(join(bundle, "root.txt"), "utf8")).trim();
  if (computed !== manifest.merkleRootSha256 || computed !== rootFile) throw new Error("Merkle root mismatch.");
  console.log(JSON.stringify({ status: "LOCAL_INTEGRITY_PASS_EXTERNAL_ANCHORS_UNVERIFIED", deploymentId: manifest.deployment?.id, evidenceCount: checked.length, merkleRootSha256: computed }));
  console.error("External Rekor inclusion and WORM retention are not verified by this local command.");
}
main().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); });
