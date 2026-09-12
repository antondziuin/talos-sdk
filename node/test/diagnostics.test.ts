import { describe, it, expect, vi } from "vitest";
import { LicenseState, TalosClient, TalosApiError, TalosSignatureError } from "../src/index.js";

describe("local diagnostic reports", () => {
  function setup() {
    const fetch = vi.fn();
    const client = new TalosClient({ productToken: "tpt_PRIVATE_PRODUCT", serverUrl: "https://user:PRIVATE_PASSWORD@example.test/private?token=PRIVATE_TOKEN", publicKey: Buffer.alloc(32).toString("base64"), hostname: "PRIVATE_HOST", fingerprintComponents: { machine_guid: "PRIVATE_HARDWARE" }, persistState: false, fetch });
    return { client, fetch };
  }

  it("never exports arbitrary API errors, options, feature values or exception messages", () => {
    const { client, fetch } = setup();
    client.current = new LicenseState("PRIVATE_DECISION", { secret: "PRIVATE_FEATURE" }, null);
    const report = client.createDiagnosticReport(new TalosApiError(403, "PRIVATE_ERROR_TOKEN"));
    expect(report).not.toContain("PRIVATE");
    expect(JSON.parse(report)).toMatchObject({ schema_version: 1, decision: "unknown", error_code: "api_error", http_status: 403 });
    expect(fetch).not.toHaveBeenCalled();
    expect(client.current.decision).toBe("PRIVATE_DECISION");
    expect(client.createDiagnosticReport(new Error("PRIVATE_ERROR_STACK"))).not.toContain("PRIVATE");
  });

  it("distinguishes signature failures, device limits and offline expiry", () => {
    const { client } = setup();
    expect(JSON.parse(client.createDiagnosticReport(new TalosSignatureError("PRIVATE_SIGNATURE")))).toMatchObject({ error_code: "signature_verification_failed", next_action: expect.stringContaining("Keep signature verification enabled") });
    expect(JSON.parse(client.createDiagnosticReport(new TalosApiError(409, "activation_limit_reached")))).toMatchObject({ error_code: "activation_limit_reached", next_action: expect.stringContaining("devices") });
    client.current = new LicenseState("grace_expired", {}, null, true, null, 123);
    expect(JSON.parse(client.createDiagnosticReport())).toMatchObject({ decision: "grace_expired", is_offline: true, grace_until: 123, error_code: null, next_action: expect.stringContaining("Reconnect") });
  });

  it("does not invent a transport cause for an offline result", () => {
    const { client } = setup();
    client.current = new LicenseState("valid", {}, null, true);
    expect(JSON.parse(client.createDiagnosticReport())).toMatchObject({ error_code: null, next_action: expect.stringContaining("cannot identify") });
  });
});
