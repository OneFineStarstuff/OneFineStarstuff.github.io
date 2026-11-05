/**
 * Structural validator for api/openapi.json (schema of record).
 *
 * WP-087 control C1: the spec is the single source of truth, so it is
 * validated on every CI run before the drift gate and the build.
 * Fictional governance-simulation artefact.
 */

import { readFileSync } from 'node:fs';

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validate(spec) {
  const errors = [];

  if (!/^3\.[01]\.\d+/.test(String(spec.openapi ?? ''))) {
    errors.push('missing or invalid openapi version (expected 3.1.x)');
  }
  if (!isPlainObject(spec.info) || !spec.info.title || !spec.info.version) {
    errors.push('info.title and info.version are required');
  }
  if (!isPlainObject(spec.paths) || Object.keys(spec.paths).length === 0) {
    errors.push('paths must be a non-empty object');
  }

  for (const [path, item] of Object.entries(spec.paths ?? {})) {
    if (!path.startsWith('/')) {
      errors.push(`path ${path} must start with /`);
    }
    if (!isPlainObject(item)) {
      errors.push(`path ${path} must be an object`);
      continue;
    }
    for (const method of Object.keys(item)) {
      if (!METHODS.includes(method)) {
        continue;
      }
      const op = item[method];
      if (!isPlainObject(op)) {
        errors.push(`${method.toUpperCase()} ${path}: operation must be an object`);
        continue;
      }
      if (!op.operationId) {
        errors.push(`${method.toUpperCase()} ${path}: operationId is required`);
      }
      if (!isPlainObject(op.responses) || Object.keys(op.responses).length === 0) {
        errors.push(`${method.toUpperCase()} ${path}: responses are required`);
      }
    }
  }

  const schemas = spec.components && isPlainObject(spec.components.schemas) ? spec.components.schemas : null;
  if (!schemas) {
    errors.push('components.schemas is required');
  } else {
    for (const [name, schema] of Object.entries(schemas)) {
      if (!isPlainObject(schema)) {
        errors.push(`schema ${name} must be an object`);
        continue;
      }
      if (schema.type === 'object' && !isPlainObject(schema.properties)) {
        errors.push(`schema ${name}: object schemas need properties`);
      }
      for (const required of schema.required ?? []) {
        if (schema.type === 'object' && !(schema.properties && required in schema.properties)) {
          errors.push(`schema ${name}: required property ${required} has no property definition`);
        }
      }
    }
  }

  return errors;
}

function main() {
  const spec = JSON.parse(readFileSync('openapi.json', 'utf8'));
  const errors = validate(spec);
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(`INVALID: ${error}`);
    }
    process.exit(1);
  }
  const pathCount = Object.keys(spec.paths).length;
  const schemaCount = Object.keys(spec.components.schemas).length;
  console.log(`openapi.json structure valid (${pathCount} paths, ${schemaCount} schemas).`);
}

main();
