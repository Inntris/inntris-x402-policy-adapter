import { privateKeyToAccount } from "viem/accounts";
import { describe, expect, it } from "vitest";

import {
  EIP3009_AUTHORIZATION_TYPES,
  verifyEip3009Signature,
} from "../../packages/pulse-conformance-evaluator/src/index.js";

describe("independent EIP-3009 verification", () => {
  it("recovers the payer and rejects non-canonical signatures", async () => {
    const account = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000002",
    );
    const authorization = {
      from: account.address,
      to: "0x000000000000000000000000000000000000dEaD",
      value: "42",
      validAfter: "100",
      validBefore: "200",
      nonce: `0x${"ab".repeat(32)}`,
    };
    const signature = await account.signTypedData({
      domain: {
        name: "Test token",
        version: "2",
        chainId: 31337n,
        verifyingContract: "0x0000000000000000000000000000000000000001",
      },
      types: EIP3009_AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        from: account.address,
        to: authorization.to,
        value: 42n,
        validAfter: 100n,
        validBefore: 200n,
        nonce: authorization.nonce,
      },
    });
    const input = {
      network: "eip155:31337",
      asset: "0x0000000000000000000000000000000000000001",
      domainName: "Test token",
      domainVersion: "2",
      authorization,
      signature,
    };

    await expect(verifyEip3009Signature(input)).resolves.toEqual({
      valid: true,
      recoveredPayer: account.address,
    });
    const badRecovery = `${signature.slice(0, -2)}00`;
    await expect(verifyEip3009Signature({ ...input, signature: badRecovery })).resolves.toEqual({
      valid: false,
    });

    const curveOrder = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    const encodedS = signature.slice(66, 130);
    const highS = (curveOrder - BigInt(`0x${encodedS}`)).toString(16).padStart(64, "0");
    const highSSignature = `${signature.slice(0, 66)}${highS}${signature.slice(130)}`;
    await expect(verifyEip3009Signature({ ...input, signature: highSSignature })).resolves.toEqual({
      valid: false,
    });
  });
});
