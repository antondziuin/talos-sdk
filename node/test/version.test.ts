import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { SDK_ID, SDK_VERSION } from "../src/version.js";

/**
 * The version the SDK reports has to be the version it is.
 *
 * `machines.sdk_version` is how a developer answers "how many of my customers
 * are still on the old client, and can I ship a breaking wire change?" — a
 * number that lags the release by however long nobody noticed makes that
 * question unanswerable while looking answered. The constant exists because the
 * package is bundled dual ESM/CJS and cannot read its own manifest at runtime;
 * this test is what keeps the constant honest.
 */
describe("sdk version", () => {
  it("matches package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    expect(SDK_VERSION).toBe(pkg.version);
  });

  it("is sent as a language-tagged id", () => {
    expect(SDK_ID).toBe(`node/${SDK_VERSION}`);
  });
});
