import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { REQUEST_DOMAIN, signedMessage } from "../src/offline.js";
import { publicKeyFromBase64, verifyKeyset, verifyManifest, verifyToken } from "../src/talos-compact.js";

/**
 * The frozen wire vectors, verified by this SDK.
 *
 * Every other verification test in this suite mints a token with a key it
 * generated moments earlier and then verifies it — the SDK agreeing with
 * itself, which is exactly what it would keep doing if the format changed on
 * both sides at once. This one reads `sdks/contract-vectors.json`: fixed keys
 * and tokens signed by the Rust server code and committed to the repository, so
 * drift shows up as three implementations disagreeing with bytes that predate
 * all of them.
 *
 * Applications pin a key and verify these shapes for years after they ship.
 * That is why the wire format is additive-only, and this is where the rule is
 * enforced rather than merely written down.
 */

type Vector = { name: string; typ: string; key: string; token: string; why?: string };
type MachineDoc = {
  domain: string;
  public_key: string;
  payload_b64: string;
  signed_message: string;
  sig: string;
};
type Doc = {
  aud: string;
  nonce: string;
  keys: Record<string, string>;
  vectors: Vector[];
  negative: Vector[];
  machine_doc: MachineDoc;
};

const doc = JSON.parse(
  readFileSync(new URL("../../contract-vectors.json", import.meta.url), "utf8"),
) as Doc;

const key = (name: string) => publicKeyFromBase64(doc.keys[name]!);

/**
 * Verify one vector through the same entry point the client uses for that token
 * class. A manifest and a keyset take different paths, and a suite that ran
 * everything through one of them would prove less than it appears to.
 */
function verifyWith(v: Vector, k: ReturnType<typeof key>): Record<string, unknown> {
  if (v.typ === "keyset") return verifyKeyset(k, doc.aud, v.token);
  if (v.typ === "manifest") return verifyManifest(k, doc.aud, v.token);
  return verifyToken(k, v.typ, doc.aud, doc.nonce, v.token);
}

const named = (name: string): Vector => {
  const v = doc.vectors.find((x) => x.name === name);
  if (!v) throw new Error(`no vector named ${name}`);
  return v;
};

describe("frozen wire vectors", () => {
  it("verifies every committed vector under the key it names", () => {
    for (const v of doc.vectors) {
      const claims = verifyWith(v, key(v.key));
      expect(claims["typ"], v.name).toBe(v.typ);
      expect(claims["aud"], v.name).toBe(doc.aud);
    }
    // A file that failed to load, or a rename that emptied the list, must not
    // read as seven passing vectors.
    expect(doc.vectors).toHaveLength(7);
  });

  it("refuses a vector under a key it does not name", () => {
    for (const v of doc.vectors) {
      for (const other of ["license", "anchor", "release"]) {
        if (other === v.key) continue;
        expect(() => verifyWith(v, key(other)), `${v.name} under ${other}`).toThrow();
      }
    }
  });

  it("builds the same signed message for a machine document as the server", () => {
    // The one document that goes the other way: signed here, verified by the
    // portal. Nothing else compares the three implementations' idea of what
    // gets signed — a typo in the domain or the version segment on one side
    // produces a request that side signs happily and the portal refuses, and
    // the symptom is a customer's file being rejected by their vendor.
    const md = doc.machine_doc;
    expect(md.domain).toBe(REQUEST_DOMAIN);
    expect(signedMessage(md.domain, md.payload_b64)).toBe(md.signed_message);

    const raw = Buffer.from(md.public_key, "base64");
    const der = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    const pub = createPublicKey({ key: der, format: "der", type: "spki" });
    expect(
      cryptoVerify(
        null,
        Buffer.from(md.signed_message, "ascii"),
        pub,
        Buffer.from(md.sig.replace(/-/g, "+").replace(/_/g, "/"), "base64"),
      ),
    ).toBe(true);
  });

  it("refuses every negative vector", () => {
    for (const v of doc.negative) {
      expect(() => verifyWith(v, key(v.key)), v.name).toThrow();
    }
    expect(doc.negative).toHaveLength(5);
  });

  /**
   * The claims an application actually reads, spelled out. The signature checks
   * above would still pass if a claim were renamed on both sides at once; these
   * are the names a deployed build looks for.
   */
  it("keeps the claims an application reads where they have always been", () => {
    const act = verifyWith(named("activation"), key("license"));
    const lic = act["lic"] as Record<string, unknown>;
    expect((lic["features"] as Record<string, unknown>)["pro"]).toBe(true);
    expect((lic["features"] as Record<string, unknown>)["seats"]).toBe(5);
    expect(lic["grace_h"]).toBe(72);
    expect(lic["reval_h"]).toBe(24);
    expect(lic["lic_exp"]).toBeNull();

    const val = verifyWith(named("validation"), key("license"));
    expect(val["decision"]).toBe("valid");
    expect(val["grace_until"] as number).toBeGreaterThan(val["server_time"] as number);

    const beat = verifyWith(named("heartbeat"), key("license"));
    expect(beat["heartbeat_interval_s"]).toBe(3600);
    expect(beat["upd"]).toBe(true);

    const lease = verifyWith(named("lease"), key("license"));
    expect(lease["max_seats"]).toBe(3);
    expect(lease["seats_in_use"]).toBe(1);
    expect(lease["inst"]).toBe("inst-1");

    // The keyset is how an application that pinned only the anchor learns the
    // licence key. If this shape moves, a rotation stops reaching the field and
    // every install fails at once.
    const keyset = verifyWith(named("keyset"), key("anchor"));
    const keys = keyset["keys"] as Array<Record<string, unknown>>;
    expect(
      keys.some(
        (k) => k["purpose"] === "license" && k["status"] === "active" && k["pk"] === doc.keys["license"],
      ),
    ).toBe(true);

    const man = verifyWith(named("manifest"), key("release"));
    expect(man["version"]).toBe("1.2.0");
    expect(man["release_seq"]).toBe(7);
    const art = (man["artifacts"] as Array<Record<string, unknown>>)[0]!;
    expect(art["filename"]).toBe("notes-1.2.0-x64.exe");
    expect((art["sha256"] as string).length).toBe(64);
  });
});
