import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const browserEntry = await readFile(new URL("../src/main.tsx", import.meta.url), "utf8");

test("browser analyzer does not transmit manifest content through network APIs", () => {
  const forbiddenNetworkCalls = [
    /\\bfetch\\s*\\(/,
    /\\bXMLHttpRequest\\b/,
    /\\bWebSocket\\b/,
    /\\bEventSource\\b/,
    /\\bsendBeacon\\s*\\(/,
    /\\bnavigator\\.serviceWorker\\b/,
  ];

  for (const pattern of forbiddenNetworkCalls) {
    assert.doesNotMatch(browserEntry, pattern, `Unexpected browser network capability: ${pattern}`);
  }
});

test("browser entry has no direct form submission endpoint", () => {
  assert.doesNotMatch(browserEntry, /<form[\\s\\S]{0,500}action=/i);
});
