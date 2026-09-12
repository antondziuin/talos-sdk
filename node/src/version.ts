/**
 * This SDK's own version, as reported to the server on activate and heartbeat.
 *
 * A constant rather than a read of `package.json`: the package ships dual
 * ESM/CJS through a bundler, so neither `import.meta.url` nor `__dirname`
 * resolves to the package root in both outputs, and a runtime read that works
 * in one build and throws in the other is worse than no read at all.
 *
 * `test/version.test.ts` asserts this equals `package.json`, so it cannot
 * quietly go stale — which is what the previous hard-coded `"node/0.0.0"`
 * literal at the call site was doing, and why the column it fills was worthless
 * for answering "who is still on the old client?".
 */
export const SDK_VERSION = "0.2.0";

/** The wire form: language tag plus version, e.g. `node/0.2.0`. */
export const SDK_ID = `node/${SDK_VERSION}`;
