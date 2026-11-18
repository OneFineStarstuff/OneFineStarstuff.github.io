import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, lstat, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { canonicalJson } from "../src/evidence/canonical.ts";
import { merkleRootFromEntries } from "../src/evidence/merkle.ts";

function arg(name: string): string {
  const index = process.argv.indexOf(`--${name}`);
  const value = index >= 0 ? process.argv[index + 1] : undefined;
  if (!value || value.startsWith("--")) throw new Error(`Missing --${name}`);
  return value;
}
function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
function safeRel(value: string): string {
  const raw = value.split(sep).join("/");
  const normalized = raw.normalize("NFC");
  if (raw !== normalized) throw new Error(`Evidence paths must already be Unicode NFC normalized: ${value}`);
  if (!normalized || normalized.startsWith("/") || normalized.split("/").some((part) => part === ".." || part === "." || part === "")) {
    throw new Error(`Unsafe evidence path: ${value}`);
  }
  return normalized;
}
async function walk(dir: string, base: string, found: string[] = []): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  entries.sort((a: any, b: any) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const entry of entries) {
    const full = join(dir, entry.name);
    const info = await lstat(full);
    if (info.isSymbolicLink()) throw new Error(`Symlinks are not allowed in evidence input: ${full}`);
    if (info.isDirectory()) await walk(full, base, found);
    else if (info.isFile()) found.push(safeRel(relative(base, full)));
    else throw new Error(`Unsupported filesystem entry in evidence input: ${full}`);
  }
  return found;
}

async function main(): Promise<void> {
  const input = resolve(arg("input"));
  const output = resolve(arg("output"));
  const deploymentId = arg("deployment-id");
  const sourceRevision = arg("source-revision");
  const image = arg("image");
  if (input === output || output.startsWith(`${input}${sep}`) || input.startsWith(`${output}${sep}`)) {
    throw new Error("Input and output directories must be separate and non-nested.");
  }
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(deploymentId)) throw new Error("Invalid deployment ID.");
  if (!/^[a-f0-9]{40,64}$/.test(sourceRevision)) throw new Error("Source revision must be a full hexadecimal commit ID.");
  if (!/@sha256:[a-f0-9]{64}$/.test(image)) throw new Error("Image must be immutable and end with @sha256:<64 lowercase hex>.");
  const inputInfo = await lstat(input);
  if (!inputInfo.isDirectory() || inputInfo.isSymbolicLink()) throw new Error("Input must be an existing non-symlink directory.");
  try { await lstat(output); throw new Error("Output directory already exists; choose a new path."); }
  catch (error: any) { if (error?.code !== "ENOENT") throw error; }

  const paths = await walk(input, input);
  paths.sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  const entries: Array<{ path: string; size: number; sha256: string }> = [];
  await mkdir(join(output, "contents"), { recursive: true });
  for (const rel of paths) {
    if (rel === "gien-bundle-metadata.json") throw new Error("The evidence input uses a reserved path: gien-bundle-metadata.json");
    const source = join(input, ...rel.split("/"));
    const destination = join(output, "contents", ...rel.split("/"));
    const bytes = await readFile(source);
    await mkdir(join(destination, ".."), { recursive: true });
    await writeFile(destination, bytes, { flag: "wx" });
    entries.push({ path: `contents/${rel}`, size: bytes.byteLength, sha256: sha256(bytes) });
  }
  const metadata = {
    format: "GIEN-EVIDENCE-BUNDLE/v1",
    hashAlgorithm: "sha-256",
    merkleConstruction: "RFC6962-domain-separated",
    deployment: { id: deploymentId, sourceRevision, image },
  };
  const metadataBytes = new TextEncoder().encode(`${canonicalJson(metadata)}\n`);
  await writeFile(join(output, "contents", "gien-bundle-metadata.json"), metadataBytes, { flag: "wx" });
  entries.push({ path: "contents/gien-bundle-metadata.json", size: metadataBytes.byteLength, sha256: sha256(metadataBytes) });
  entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const root = merkleRootFromEntries(entries);
  const manifest = { ...metadata, evidenceCount: entries.length, entries, merkleRootSha256: root };
  await writeFile(join(output, "manifest.json"), `${canonicalJson(manifest)}\n`, { flag: "wx" });
  await writeFile(join(output, "root.txt"), `${root}\n`, { flag: "wx" });
  console.log(JSON.stringify({ status: "BUILT", deploymentId, evidenceCount: entries.length, merkleRootSha256: root, output }));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
