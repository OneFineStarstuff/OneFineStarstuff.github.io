import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";

const html = await readFile("dist/index.html", "utf8");
assert.match(html, /<div id="root">/, "production HTML must include the React mount point");

const assetRefs = [...html.matchAll(/(?:src|href)="([^"]+\.(?:js|css))"/g)].map((match) => match[1]);
assert.ok(assetRefs.some((path) => path.endsWith(".js")), "production HTML must reference a JS asset");
assert.ok(assetRefs.some((path) => path.endsWith(".css")), "production HTML must reference a CSS asset");

for (const ref of assetRefs) {
  const relative = ref.replace(/^\.?\//, "");
  assert.ok(relative.startsWith("assets/"), `unexpected external or non-asset reference: ${ref}`);
  const file = await stat(`dist/${relative}`);
  assert.ok(file.size > 0, `built asset must not be empty: ${ref}`);
}

const javascript = await readFile(`dist/${assetRefs.find((path) => path.endsWith(".js")).replace(/^\.?\//, "")}`, "utf8");
for (const marker of ["/dashboard", "/risk-indices", "/compliance", "/digital-twin", "DEMO MODE"]) {
  assert.ok(javascript.includes(marker), `production bundle should contain expected app marker: ${marker}`);
}

const port = Number(process.env.GIEN_SMOKE_PORT ?? 4179);
const origin = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ["node_modules/vite/bin/vite.js", "preview", "--host", "127.0.0.1", "--port", String(port), "--strictPort"], {
  stdio: ["ignore", "pipe", "pipe"],
});
let serverOutput = "";
server.stdout.setEncoding("utf8").on("data", (chunk) => { serverOutput += chunk; });
server.stderr.setEncoding("utf8").on("data", (chunk) => { serverOutput += chunk; });

try {
  let ready = false;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    if (server.exitCode !== null) break;
    try {
      const response = await fetch(origin);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      // Vite preview is still starting.
    }
    await delay(250);
  }

  assert.ok(ready, `Vite preview did not become healthy. Output:\n${serverOutput}`);

  for (const route of ["/", "/dashboard", "/risk-indices", "/compliance", "/digital-twin", "/submission-packages"]) {
    const response = await fetch(new URL(route, origin));
    assert.equal(response.status, 200, `SPA route should be served by preview: ${route}`);
    assert.match(response.headers.get("content-type") ?? "", /text\/html/, `route should return HTML: ${route}`);
    const body = await response.text();
    assert.match(body, /id="root"/, `route should include React mount point: ${route}`);
    assert.match(body, /\.js/, `route should reference application code: ${route}`);
  }

  for (const ref of assetRefs) {
    const response = await fetch(new URL(ref, origin));
    assert.equal(response.status, 200, `built asset should load over HTTP: ${ref}`);
    assert.ok((await response.arrayBuffer()).byteLength > 0, `served asset should not be empty: ${ref}`);
  }

  console.log(`GIEN production smoke test passed: ${assetRefs.length} assets, 6 SPA routes, port ${port}.`);
} finally {
  server.kill("SIGTERM");
}
