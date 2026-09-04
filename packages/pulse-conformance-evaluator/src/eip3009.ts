import { authorizationTypes } from "@x402/evm";
import { recoverTypedDataAddress, type Address, type Hex } from "viem";

import type { Eip3009Authorization } from "./types.js";
import { normaliseAddress } from "./values.js";

const SECP256K1_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_ORDER = SECP256K1_ORDER / 2n;
const MAX_UINT256 = (1n << 256n) - 1n;

export const EIP3009_AUTHORIZATION_TYPES = authorizationTypes;

export interface Eip3009SignatureInput {
  network: string;
  asset: string;
  domainName: string;
  domainVersion: string;
  authorization: Eip3009Authorization;
  signature: string;
}

export interface Eip3009SignatureResult {
  valid: boolean;
  recoveredPayer?: Address | undefined;
}

function chainIdFromNetwork(network: string): bigint | undefined {
  const match = /^eip155:(0|[1-9]\d*)$/u.exec(network);
  if (match?.[1] === undefined) return undefined;
  try {
    const value = BigInt(match[1]);
    return value > 0n && value <= MAX_UINT256 ? value : undefined;
  } catch {
    return undefined;
  }
}

function hasCanonicalSignature(signature: string): boolean {
  if (!/^0x[0-9a-fA-F]{130}$/u.test(signature)) return false;
  const bytes = Buffer.from(signature.slice(2), "hex");
  const r = BigInt(`0x${bytes.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${bytes.subarray(32, 64).toString("hex")}`);
  const recovery = bytes[64];
  return (
    r > 0n &&
    r < SECP256K1_ORDER &&
    s > 0n &&
    s <= SECP256K1_HALF_ORDER &&
    (recovery === 27 || recovery === 28)
  );
}

export async function verifyEip3009Signature(
  input: Eip3009SignatureInput,
): Promise<Eip3009SignatureResult> {
  if (!hasCanonicalSignature(input.signature)) return { valid: false };
  const chainId = chainIdFromNetwork(input.network);
  const verifyingContract = normaliseAddress(input.asset);
  const from = normaliseAddress(input.authorization.from);
  const to = normaliseAddress(input.authorization.to);
  if (
    chainId === undefined ||
    verifyingContract === undefined ||
    from === undefined ||
    to === undefined
  ) {
    return { valid: false };
  }
  try {
    const recoveredPayer = await recoverTypedDataAddress({
      domain: {
        name: input.domainName,
        version: input.domainVersion,
        chainId,
        verifyingContract,
      },
      types: authorizationTypes,
      primaryType: "TransferWithAuthorization",
      message: {
        from,
        to,
        value: BigInt(input.authorization.value),
        validAfter: BigInt(input.authorization.validAfter),
        validBefore: BigInt(input.authorization.validBefore),
        nonce: input.authorization.nonce as Hex,
      },
      signature: input.signature as Hex,
    });
    return { valid: recoveredPayer === from, recoveredPayer };
  } catch {
    return { valid: false };
  }
}
