#!/usr/bin/env node
// B7 (WP-114): validate compliance/crosswalk.yaml against schemas/crosswalk.schema.json.
// Install once: npm i -D yaml ajv
// Exit codes: 0 valid; 1 schema violation; 2 missing deps.
import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import Ajv from 'ajv';

const doc = YAML.parse(readFileSync('compliance/crosswalk.yaml', 'utf-8'));
const schema = JSON.parse(readFileSync('schemas/crosswalk.schema.json', 'utf-8'));
const validate = new Ajv({ allErrors: true }).compile(schema);
if (!validate(doc)) {
  console.error('CROSSWALK INVALID:', JSON.stringify(validate.errors, null, 2));
  process.exit(1);
}
console.log('CROSSWALK VALID (' + doc.regimes.length + ' regimes, catalog rev ' + doc.catalog_rev + ')');
