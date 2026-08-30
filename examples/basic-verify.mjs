/**
 * Minimal verifyConditions example — Node.js, headless.
 *
 * Licensed EVM calls require a wallet-ownership proof, so this example
 * signs the challenge with a local key via viem (the one extra install):
 *
 *   npm i viem
 *   SKYE_LICENSE_KEY=SKYE-... WALLET_KEY=0x<private-key> DOMAIN=yourdomain.com \\
 *     node examples/basic-verify.mjs
 *
 * WALLET_KEY is the private key of the wallet being verified — you are
 * proving control of it, which is the point. Never use a key that holds
 * real funds for experiments.
 */
import { privateKeyToAccount } from 'viem/accounts';
import { proveWalletOwnership, verifyConditions } from '../build/index.js';

const licenseKey = process.env.SKYE_LICENSE_KEY;
const walletKey = process.env.WALLET_KEY;
const domain = process.env.DOMAIN; // required outside a browser
if (!licenseKey || !walletKey || !domain) {
  console.error('Set SKYE_LICENSE_KEY, WALLET_KEY, and DOMAIN.');
  process.exit(1);
}

const account = privateKeyToAccount(walletKey);

const proof = await proveWalletOwnership({
  address: account.address,
  domain,
  signMessage: (message) => account.signMessage({ message }),
});
if (!proof.proofToken) {
  console.error('Proof failed:', proof.error);
  process.exit(1);
}

const result = await verifyConditions({
  address: account.address,
  conditions: [
    { type: 'token_balance', contractAddress: 'native', chainId: 1, threshold: 0.000001 },
  ],
  licenseKey,
  domain,
  walletProof: proof.proofToken,
});

console.log('pass:', result.pass);
console.log('jwt:', result.jwt ? result.jwt.slice(0, 40) + '…' : null);
if (result.error) console.error('error:', result.error);
