import { readFile } from 'node:fs/promises';
import { resolve, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const root = resolve(new URL('..', import.meta.url).pathname);
const breakingKeywords = [
  'type', 'format', 'const', 'enum', 'pattern', 'minimum', 'maximum',
  'exclusiveMinimum', 'exclusiveMaximum', 'minLength', 'maxLength',
  'minItems', 'maxItems', 'additionalProperties', 'oneOf', 'anyOf', 'not',
];

function fail(message) { throw new Error(message); }
function assert(condition, message) { if (!condition) fail(message); }

function assertSchemaStructure(schema) {
  assert(schema && schema.type === 'object', 'Release schema must be a JSON Schema object.');
  assert(schema.additionalProperties === false, 'Release schema must reject unknown top-level fields.');
  const required = new Set(schema.required ?? []);
  for (const key of ['releaseId','imageDigest','schema','contracts','build','signature','sbom','vulnerabilityScan','admission','freeze','change']) {
    assert(required.has(key), `Release schema missing required property: ${key}`);
    assert(schema.properties?.[key], `Release schema missing property definition: ${key}`);
  }
  assert(schema.properties.imageDigest.pattern === '^sha256:[a-f0-9]{64}$', 'Image digest must be a lowercase SHA-256 digest.');
  assert(schema.properties.breakGlass?.additionalProperties === false, 'Break-glass schema must reject unknown fields.');
}

function assertContractStructure(openapi, schema) {
  assert(openapi?.openapi === '3.1.0', 'OpenAPI contract must use version 3.1.0.');
  assert(openapi.info?.title && openapi.info?.version, 'OpenAPI info title and version are required.');
  for (const [path, method] of [
    ['/healthz','get'], ['/readyz','get'], ['/v1/changes/classify','post'], ['/v1/release/evaluate','post'],
  ]) assert(openapi.paths?.[path]?.[method], `OpenAPI operation missing: ${method.toUpperCase()} ${path}`);
  const releaseRef = openapi.paths['/v1/release/evaluate'].post.requestBody?.content?.['application/json']?.schema?.$ref;
  assert(releaseRef === '#/components/schemas/ReleaseEvaluation', 'Release endpoint must reference the canonical ReleaseEvaluation schema.');
  assert(openapi.components?.schemas?.ReleaseEvaluation?.$ref === '../schemas/release-evaluation.schema.json', 'OpenAPI ReleaseEvaluation must resolve to the canonical JSON Schema file.');
  assert(schema.properties?.build?.additionalProperties === false, 'Build evidence schema must reject unknown fields.');
}

function compareSchema(previous, current, path = '$') {
  if (current.additionalProperties === false && previous.additionalProperties !== false) {
    fail(`Unknown-field policy was tightened at ${path}; compatibility review required.`);
  }
  if (previous.type !== current.type) fail(`Breaking schema type change at ${path}: ${previous.type} -> ${current.type}`);
  const oldRequired = new Set(previous.required ?? []);
  const newRequired = new Set(current.required ?? []);
  for (const key of oldRequired) if (!newRequired.has(key)) {
    // Relaxing a required constraint is not a request-compatibility break; report only as review-worthy.
  }
  for (const key of newRequired) if (!oldRequired.has(key)) fail(`New required field at ${path}.${key} is a breaking request-schema change.`);
  const oldProps = previous.properties ?? {};
  const newProps = current.properties ?? {};
  for (const key of Object.keys(oldProps)) {
    if (!(key in newProps)) fail(`Removed property at ${path}.${key} is a breaking schema change.`);
    compareSchema(oldProps[key], newProps[key], `${path}.${key}`);
  }
  for (const keyword of breakingKeywords) {
    if (keyword === 'type') continue;
    if (!(keyword in previous)) continue;
    if (!(keyword in current)) fail(`Removed constraint '${keyword}' at ${path}; manual compatibility review required.`);
    const before = previous[keyword];
    const after = current[keyword];
    if (keyword === 'enum') {
      if (!Array.isArray(after) || !before.every((value) => after.includes(value))) fail(`Enum narrowed at ${path}.`);
      continue;
    }
    if (keyword === 'minimum' || keyword === 'exclusiveMinimum' || keyword === 'minLength' || keyword === 'minItems') {
      if (typeof after !== 'number' || after > before) fail(`Constraint '${keyword}' tightened at ${path}.`);
      continue;
    }
    if (keyword === 'maximum' || keyword === 'exclusiveMaximum' || keyword === 'maxLength' || keyword === 'maxItems') {
      if (typeof after !== 'number' || after < before) fail(`Constraint '${keyword}' tightened at ${path}.`);
      continue;
    }
    if (JSON.stringify(before) !== JSON.stringify(after)) fail(`Changed constraint '${keyword}' at ${path}; compatibility review required.`);
  }
  if (previous.items) {
    assert(current.items, `Removed array item schema at ${path}.`);
    compareSchema(previous.items, current.items, `${path}[]`);
  }
}

function assertOpenApiCompatible(previous, current) {
  const oldReleaseRef = previous.components?.schemas?.ReleaseEvaluation?.$ref;
  const newReleaseRef = current.components?.schemas?.ReleaseEvaluation?.$ref;
  if (oldReleaseRef && oldReleaseRef !== newReleaseRef) fail('Changed canonical ReleaseEvaluation schema reference.');
  for (const [path, pathItem] of Object.entries(previous.paths ?? {})) {
    assert(current.paths?.[path], `Removed API path ${path}.`);
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!['get','post','put','patch','delete','head','options','trace'].includes(method)) continue;
      const next = current.paths[path][method];
      assert(next, `Removed operation ${method.toUpperCase()} ${path}.`);
      if (operation.operationId) assert(next.operationId === operation.operationId, `Changed operationId for ${method.toUpperCase()} ${path}.`);
      for (const code of Object.keys(operation.responses ?? {})) {
        assert(next.responses?.[code], `Removed response ${code} from ${method.toUpperCase()} ${path}.`);
      }
    }
  }
}

function readGitFile(ref, file) {
  const top = spawnSync('git', ['rev-parse', '--show-toplevel'], { cwd: root, encoding: 'utf8' });
  const gitRoot = top.status === 0 ? top.stdout.trim() : root;
  const projectPrefix = relative(gitRoot, root);
  const repositoryPath = projectPrefix && projectPrefix !== '.' ? `${projectPrefix.split(sep).join('/')}/${file}` : file;
  const result = spawnSync('git', ['show', `${ref}:${repositoryPath}`], { cwd: gitRoot, encoding: 'utf8' });
  if (result.status !== 0) {
    const stderr = result.stderr || '';
    // A first-time API subproject has no baseline files. Treat that as an initial introduction,
    // but fail closed when git show failed for any other reason.
    if (stderr.includes('exists on disk, but not in') || stderr.includes('does not exist in')) return null;
    fail(`Could not read baseline ${ref}:${file}: ${stderr || result.error || 'git show failed'}`);
  }
  return result.stdout;
}

export { assertSchemaStructure, assertContractStructure, compareSchema, assertOpenApiCompatible };

async function main() {
  const openapi = JSON.parse(await readFile(resolve(root, 'api/openapi.json'), 'utf8'));
  const schema = JSON.parse(await readFile(resolve(root, 'schemas/release-evaluation.schema.json'), 'utf8'));
  assertSchemaStructure(schema);
  assertContractStructure(openapi, schema);
  const baseArg = process.argv.indexOf('--base-ref');
  if (baseArg >= 0) {
    const ref = process.argv[baseArg + 1];
    if (!ref || !/^[A-Za-z0-9._/-]+$/.test(ref)) fail('Invalid --base-ref value.');
    const baseOpenApiText = readGitFile(ref, 'api/openapi.json');
    const baseSchemaText = readGitFile(ref, 'schemas/release-evaluation.schema.json');
    if (baseOpenApiText === null && baseSchemaText === null) {
      console.log(`INFO: no prior API/schema baseline exists at ${ref}; validating this as the initial contract introduction.`);
    } else {
      assert(baseOpenApiText !== null && baseSchemaText !== null, 'Only one baseline API/schema file exists; refusing partial compatibility comparison.');
      const baseOpenApi = JSON.parse(baseOpenApiText);
      const baseSchema = JSON.parse(baseSchemaText);
      assertOpenApiCompatible(baseOpenApi, openapi);
      compareSchema(baseSchema, schema);
    }
  }
  console.log(`PASS: OpenAPI 3.1.0 contract and release JSON Schema validated${baseArg >= 0 ? ' against backward-compatibility baseline' : ''}.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); });
}
