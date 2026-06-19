#!/usr/bin/env node
/* Compile the OmegaActual contracts with solc 0.8.26 and report errors/warnings.
 * Exits non-zero on any compilation ERROR (warnings are tolerated/reported). */
const fs = require("fs");
const path = require("path");
const solc = require("solc");

const targets = [
  { name: "OmegaActualTreatyEngineHardened.sol", file: path.join(__dirname, "OmegaActualTreatyEngineHardened.sol") },
  { name: "OmegaActualTreatyEngine.sol", file: path.join(__dirname, "..", "OmegaActualTreatyEngine.sol") },
];

let hadError = false;
for (const t of targets) {
  if (!fs.existsSync(t.file)) { console.log(`  SKIP ${t.name} (missing)`); continue; }
  const input = {
    language: "Solidity",
    sources: { [t.name]: { content: fs.readFileSync(t.file, "utf8") } },
    settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } } },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errors = (out.errors || []).filter((e) => e.severity === "error");
  const warnings = (out.errors || []).filter((e) => e.severity === "warning");
  if (errors.length) {
    hadError = true;
    console.log(`  FAIL ${t.name}: ${errors.length} error(s)`);
    errors.forEach((e) => console.log("    " + e.formattedMessage.split("\n")[0]));
  } else {
    const contractName = Object.keys(out.contracts[t.name])[0];
    const bytecode = out.contracts[t.name][contractName].evm.bytecode.object;
    console.log(`  OK   ${t.name} -> ${contractName} (bytecode ${bytecode.length / 2} bytes, ${warnings.length} warning(s))`);
  }
}
process.exit(hadError ? 1 : 0);
