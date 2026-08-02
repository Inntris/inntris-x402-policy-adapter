import { OFFICIAL_X402_TESTNET_FACILITATOR, probeX402Sandbox } from "@inntris/x402-adapter";

const configuredUrl = process.env.INNTRIS_X402_FACILITATOR_URL?.trim();
const report = await probeX402Sandbox({
  facilitatorUrl:
    configuredUrl === undefined || configuredUrl === ""
      ? OFFICIAL_X402_TESTNET_FACILITATOR
      : configuredUrl,
});

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
