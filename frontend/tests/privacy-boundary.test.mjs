import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const sourceRoot = fileURLToPath(new URL("../src/", import.meta.url));

async function listBrowserSources(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await listBrowserSources(path));
    else if (entry.isFile() && [".ts", ".tsx", ".js", ".jsx"].includes(extname(entry.name))) files.push(path);
  }
  return files;
}

const sourceFiles = await listBrowserSources(sourceRoot);
const browserSources = await Promise.all(sourceFiles.map(async (path) => ({
  path: relative(sourceRoot, path),
  content: await readFile(path, "utf8"),
})));

test("all browser-loaded source modules avoid direct network APIs", () => {
  const forbiddenNetworkCalls = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bWebSocket\b/,
    /\bEventSource\b/,
    /\bsendBeacon\s*\(/,
    /\bnavigator\.serviceWorker\b/,
  ];

  assert.ok(browserSources.length > 0, "Expected browser source modules to be inspected");
  for (const source of browserSources) {
    for (const pattern of forbiddenNetworkCalls) {
      assert.doesNotMatch(source.content, pattern, source.path + " contains an unexpected browser network capability: " + pattern);
    }
  }
});

test("browser source modules have no direct form submission endpoint", () => {
  for (const source of browserSources) {
    assert.doesNotMatch(source.content, /<form\b[^>]*\baction\s*=/i, source.path + " contains a direct form action");
  }
});
