import { mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { TalosClient, type FetchLike } from "../src/client.js";
import { TalosError } from "../src/errors.js";

/**
 * A licensing call that never comes back.
 *
 * Node's `fetch` has no default timeout, so before `httpTimeoutMs` existed a
 * server that accepted the connection and then said nothing left `activate()`
 * and `validate()` pending forever. In a desktop application that is a splash
 * screen that never goes away, on the one code path a user cannot skip — and it
 * is invisible in every test that uses a fetch double, because a double always
 * answers.
 *
 * So the assertions are about the shape of the failure as much as the fact of
 * it: an abort has to arrive as a Talos error, because `validate` turns a
 * *network* failure into the grace-period path and would let anything else
 * through to take the application down.
 */
describe("httpTimeoutMs", () => {
  const options = () => ({
    productToken: "tpt_test",
    publicKey: Buffer.alloc(32).toString("base64"),
    serverUrl: "http://127.0.0.1:9",
    statePath: path.join(mkdtempSync(path.join(os.tmpdir(), "talos-timeout-")), "state.json"),
  });

  /** A fetch that answers only when it is aborted, which is the case at issue. */
  const hangs: FetchLike = (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => {
        const e = new Error("aborted");
        e.name = "TimeoutError";
        reject(e);
      });
    });

  it("abandons a call that never answers", async () => {
    const client = new TalosClient({ ...options(), fetch: hangs, httpTimeoutMs: 60 });
    const started = Date.now();
    await expect(client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")).rejects.toThrow(TalosError);
    // Bounded by the option rather than by the runtime's own patience, which is
    // what "no default timeout" means: without this the promise never settles
    // and the assertion above would hang instead of failing.
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("reports the timeout as a Talos error, not a raw abort", async () => {
    const client = new TalosClient({ ...options(), fetch: hangs, httpTimeoutMs: 60 });
    // The message matters: `validate` catches Talos errors to enter the grace
    // period, and an `AbortError` escaping instead would stop the application
    // rather than let it keep running offline.
    await expect(client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")).rejects.toThrow(/timed out/);
  });

  it("passes a signal by default, without being asked", async () => {
    // The default is the point. An option nobody sets protects nobody, and the
    // state this replaces is "no timeout at all".
    let sawSignal: unknown = "never called";
    const capture: FetchLike = (_url, init) => {
      sawSignal = init.signal;
      const e = new Error("stop here");
      e.name = "TimeoutError";
      return Promise.reject(e);
    };
    const client = new TalosClient({ ...options(), fetch: capture });
    await expect(client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")).rejects.toThrow(TalosError);
    expect(sawSignal).toBeInstanceOf(AbortSignal);
  });

  it("sends no signal when the timeout is disabled", async () => {
    // `0` is an escape hatch for a host that manages its own deadlines, and it
    // has to actually disable rather than clamp to the default — otherwise the
    // escape hatch is decoration.
    let sawSignal: unknown = "never called";
    const capture: FetchLike = (_url, init) => {
      sawSignal = init.signal;
      return Promise.reject(new Error("stop here"));
    };
    const client = new TalosClient({ ...options(), fetch: capture, httpTimeoutMs: 0 });
    await expect(client.activate("XXXXX-XXXXX-XXXXX-XXXXX-XXXXX")).rejects.toThrow();
    expect(sawSignal).toBeUndefined();
  });
});
