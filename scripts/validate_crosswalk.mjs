#!/usr/bin/env node
// B7 (WP-114): validate compliance/crosswalk.yaml against the 2020-12 schema.
// Install once: npm i -D yaml ajv
// Exit codes: 0 valid; 1 schema violation; 2 missing dependencies.
import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import Ajv2020 from 'ajv/dist/2020.js';

const doc = YAML.parse(readFileSync('compliance/crosswalk.yaml', 'utf-8'));
const schema = JSON.parse(readFileSync('schemas/crosswalk.schema.json', 'utf-8'));
const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

if (!validate(doc)) {
  console.error('CROSSWALK INVALID:', JSON.stringify(validate.errors, null, 2));
  process.exit(1);
}

console.log(
  'CROSSWALK VALID (' +
    doc.regimes.length +
    ' regimes, catalog rev ' +
    doc.catalog_rev +
    ')',
);
