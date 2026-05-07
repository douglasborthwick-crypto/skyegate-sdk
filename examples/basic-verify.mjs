/**
 * Minimal verifyConditions example.
 *
 * Usage:
 *   SKYE_LICENSE_KEY=SKYE_... WALLET=0x... node examples/basic-verify.mjs
 *
 * Asks the SkyeMeta proxy whether the wallet holds at least 0.0001 ETH on
 * Ethereum mainnet, and prints the result + signed JWT.
 */

import { verifyConditions } from '../build/index.js';

const licenseKey = process.env.SKYE_LICENSE_KEY;
const wallet = process.env.WALLET;

if (!licenseKey || !wallet) {
  console.error('Set SKYE_LICENSE_KEY and WALLET env vars.');
  process.exit(1);
}

const result = await verifyConditions({
  address: wallet,
  conditions: [
    {
      type: 'token_balance',
      contractAddress: 'native',
      chainId: 1,
      threshold: 0.0001,
    },
  ],
  licenseKey,
});

console.log('pass:', result.pass);
console.log('jwt:',  result.jwt ? result.jwt.slice(0, 60) + '...' : null);
if (result.error) console.log('error:', result.error);
