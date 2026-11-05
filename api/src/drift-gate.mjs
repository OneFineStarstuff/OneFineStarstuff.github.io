/**
 * Schema drift gate (WP-087 control C1).
 *
 * Compares the candidate spec (api/openapi.json) against the approved
 * baseline snapshot (api/snapshots/openapi.baseline.json) and classifies
 * every detected change:
 *
 *   - NON-BREAKING: added paths, methods, schemas, or optional properties;
 *     removal of optional properties.
 *   - BREAKING: removed paths, methods, or schemas; removed required
 *     properties; changed property types; added required properties.
 *
 * Verdicts:
 *   - GREEN: no breaking change detected (exit 0).
 *   - BLOCK: breaking change detected and no approval (exit 1).
 *   - APPROVED: breaking change detected but approved via the
 *     GIEN_APPROVE_BREAKING=1 environment variable, which must only be set
 *     after a second-reviewer sign-off (four-eyes, per WP-087 C1/C7).
 *
 * The gate inspects top-level schema properties; nested object properties
 * are intentionally out of scope for phase P1 and are covered by the
 * payload shape tests in test/api-shape.test.mjs.
 *
 * Fictional governance-simulation artefact.
 */

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const PATH_ITEM_META_KEYS = ['parameters', 'summary', 'description', 'servers'];

export function classifyDrift(baseline, candidate) {
  const breaking = [];
  const nonBreaking = [];

  const baselinePaths = baseline && typeof baseline === 'object' && baseline.paths ? baseline.paths : {};
  const candidatePaths = candidate && typeof candidate === 'object' && candidate.paths ? candidate.paths : {};

  for (const [path, item] of Object.entries(baselinePaths)) {
    if (!(path in candidatePaths)) {
      breaking.push(`removed path ${path}`);
      continue;
    }
    for (const method of Object.keys(item)) {
      if (PATH_ITEM_META_KEYS.includes(method) || method.startsWith('x-')) {
        continue;
      }
      if (!(method in candidatePaths[path])) {
        breaking.push(`removed operation ${method.toUpperCase()} ${path}`);
      }
    }
  }
  for (const path of Object.keys(candidatePaths)) {
    if (!(path in baselinePaths)) {
      nonBreaking.push(`added path ${path}`);
    }
  }

  const baselineSchemas =
    baseline && baseline.components && baseline.components.schemas ? baseline.components.schemas : {};
  const candidateSchemas =
    candidate && candidate.components && candidate.components.schemas ? candidate.components.schemas : {};

  for (const [name, baselineSchema] of Object.entries(baselineSchemas)) {
    if (!(name in candidateSchemas)) {
      breaking.push(`removed schema ${name}`);
      continue;
    }
    const candidateSchema = candidateSchemas[name];
    const baselineProps = baselineSchema && baselineSchema.properties ? baselineSchema.properties : {};
    const candidateProps = candidateSchema && candidateSchema.properties ? candidateSchema.properties : {};
    const baselineRequired = Array.isArray(baselineSchema && baselineSchema.required)
      ? baselineSchema.required
      : [];
    const candidateRequired = Array.isArray(candidateSchema && candidateSchema.required)
      ? candidateSchema.required
      : [];

    for (const [prop, baselineProp] of Object.entries(baselineProps)) {
      if (!(prop in candidateProps)) {
        if (baselineRequired.includes(prop)) {
          breaking.push(`removed required property ${name}.${prop}`);
        } else {
          nonBreaking.push(`removed optional property ${name}.${prop}`);
        }
        continue;
      }
      const baselineType = JSON.stringify(baselineProp && baselineProp.type);
      const candidateType = JSON.stringify(candidateProps[prop] && candidateProps[prop].type);
      if (baselineType !== candidateType) {
        breaking.push(`changed type of ${name}.${prop} (${baselineType} -> ${candidateType})`);
      }
    }

    for (const prop of Object.keys(candidateProps)) {
      if (prop in baselineProps) {
        continue;
      }
      if (candidateRequired.includes(prop)) {
        breaking.push(`added required property ${name}.${prop}`);
      } else {
        nonBreaking.push(`added optional property ${name}.${prop}`);
      }
    }
  }

  for (const name of Object.keys(candidateSchemas)) {
    if (!(name in baselineSchemas)) {
      nonBreaking.push(`added schema ${name}`);
    }
  }

  return {
    verdict: breaking.length > 0 ? 'BLOCK' : 'GREEN',
    breaking,
    nonBreaking,
  };
}

export function main() {
  const baseline = JSON.parse(readFileSync('snapshots/openapi.baseline.json', 'utf8'));
  const candidate = JSON.parse(readFileSync('openapi.json', 'utf8'));
  const result = classifyDrift(baseline, candidate);

  for (const note of result.nonBreaking) {
    console.log(`NON-BREAKING: ${note}`);
  }
  for (const note of result.breaking) {
    console.log(`BREAKING: ${note}`);
  }

  if (result.verdict === 'BLOCK') {
    if (process.env.GIEN_APPROVE_BREAKING === '1') {
      console.log('APPROVED: breaking change approved via GIEN_APPROVE_BREAKING=1 (four-eyes sign-off per WP-087 C1).');
      return;
    }
    console.error('BLOCK: unapproved breaking change detected. Obtain second-reviewer sign-off, update the baseline snapshot deliberately, or split the change.');
    process.exit(1);
  }
  console.log('Drift gate GREEN: no unapproved breaking change against the baseline snapshot.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
