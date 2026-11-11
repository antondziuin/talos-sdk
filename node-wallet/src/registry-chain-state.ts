import type { Hex } from "viem";
import { checkHex } from "./protocol.js";
import { RegistryLicenseError } from "./registry-protocol.js";

export interface RegistryBlock { number: bigint; tag: Hex; hash: Hex; timestamp: number }
export interface RegistryChainState {
  v: 1;
  head: { number: string; hash: Hex; timestamp: number };
  licenses: Record<string, { revision: number; revoked: boolean }>;
}

export function registryBlock(value: unknown): RegistryBlock {
  try {
    const b = value as Record<string, unknown>;
    if (!b || typeof b.number !== "string" || !/^0x[0-9a-f]+$/i.test(b.number)
      || typeof b.timestamp !== "string" || !/^0x[0-9a-f]+$/i.test(b.timestamp)) throw new Error();
    checkHex(b.hash, 32);
    const number = BigInt(b.number), timestamp = Number(BigInt(b.timestamp));
    if (number > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(timestamp) || timestamp < 0) throw new Error();
    return { number, tag: b.number as Hex, hash: b.hash.toLowerCase() as Hex, timestamp };
  } catch { throw new RegistryLicenseError("invalid_registry_rpc_response"); }
}

export function registryChainState(value?: string): RegistryChainState | undefined {
  if (value === undefined) return undefined;
  try {
    if (value.length > 32768) throw new Error();
    const state = JSON.parse(value) as RegistryChainState;
    if (state?.v !== 1 || !state.head || typeof state.head.number !== "string" || !/^(0|[1-9][0-9]*)$/.test(state.head.number)
      || BigInt(state.head.number) > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(state.head.timestamp)
      || state.head.timestamp < 0 || !state.licenses || typeof state.licenses !== "object" || Array.isArray(state.licenses)
      || Object.keys(state.licenses).length > 64) throw new Error();
    checkHex(state.head.hash, 32);
    for (const [id, observation] of Object.entries(state.licenses)) {
      checkHex(id, 32);
      if (id !== id.toLowerCase() || !observation || !Number.isSafeInteger(observation.revision) || observation.revision < 0 || typeof observation.revoked !== "boolean") throw new Error();
    }
    return state;
  } catch { throw new RegistryLicenseError("invalid_registry_chain_state"); }
}

export const sameRegistryHead = (a: RegistryChainState["head"], b: RegistryChainState["head"]) =>
  a.number === b.number && a.hash.toLowerCase() === b.hash.toLowerCase() && a.timestamp === b.timestamp;
