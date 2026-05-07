# @skyemeta/skyegate

Condition-based content gating for Vercel / Next.js. Wallet-verified access to pages, posts, files, or API routes — gated by a signed boolean from [InsumerAPI](https://insumermodel.com/developers/) (token balance, NFT ownership, EAS attestation, or Farcaster identity). Companion to the [SkyeGate Pro WordPress plugin](https://skyemeta.com/skyegate/) — same SKYE license key, same conditions, same proxy. **One license, two stacks.**

```bash
npm install @skyemeta/skyegate
```

Bring your own wallet stack — wagmi, RainbowKit, ConnectKit, Privy, whatever your Next.js app already uses. This SDK only provides the gating layer.

## Quick start

You need a SKYE license key. [Buy one for $49/mo or $350/yr at skyemeta.com/skyegate](https://skyemeta.com/skyegate/) — same key works on the WordPress plugin and this SDK.

### 1. Client: verify the wallet

```tsx
'use client';
import { useAccount } from 'wagmi';
import { GatedContent } from '@skyemeta/skyegate/react';

export default function Page() {
  const { address } = useAccount();

  return (
    <GatedContent
      address={address}
      conditions={[{ type: 'farcaster_id' }]}
      licenseKey={process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!}
      loading={<p>Verifying...</p>}
      fallback={<p>Connect a Farcaster-linked wallet to view this.</p>}
      onPass={async (jwt) => {
        const res = await fetch('/api/gated-content', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jwt }),
        });
        const { secret } = await res.json();
        // render `secret` somewhere
      }}
    >
      <p>Welcome, Farcaster user.</p>
    </GatedContent>
  );
}
```

### 2. Server: validate the JWT before serving gated content

```ts
// app/api/gated-content/route.ts
import { validateContentToken } from '@skyemeta/skyegate';

export async function POST(req: Request) {
  const { jwt } = await req.json();
  const result = await validateContentToken(jwt, {
    expectedConditions: [{ type: 'farcaster_id' }],
  });
  if (!result.pass) {
    return Response.json({ error: result.error }, { status: 403 });
  }
  return Response.json({ secret: 'Real gated content here.' });
}
```

The browser only ever receives the gated content after the JWT clears server-side validation. The text isn't in the page source or the bundle — it's fetched only after a signed verification.

## API

### `verifyConditions(params)` → `Promise<VerifyConditionsResult>`

Low-level imperative call. The React hook + component use this internally.

| Field | Type | Notes |
|---|---|---|
| `address` | `string` | Wallet address (EVM hex or Solana base58) |
| `conditions` | `Condition[]` | One or more conditions; `pass=true` requires *all* to be met |
| `licenseKey` | `string` | Your `SKYE_xxx...` key |
| `walletType` | `'evm'` \| `'solana'` | Default `'evm'` |
| `endpoint` | `string` | Override the proxy URL (advanced) |

Returns `{ pass, jwt, raw, error? }`. On `pass:true`, hand `jwt` to your server endpoint and call `validateContentToken` there.

### `validateContentToken(jwt, options?)` → `Promise<ValidateContentTokenResult>`

Server-side JWT validation. Verifies the ECDSA P-256 signature against InsumerAPI's JWKS, checks issuer + expiry, and (optionally) confirms the signed conditions match what your route requires.

| Option | Type | Notes |
|---|---|---|
| `jwksUrl` | `string` | Default: InsumerAPI's public JWKS |
| `issuer` | `string` | Default: `https://api.insumermodel.com` |
| `expectedConditions` | `Condition[]` | Replay protection — JWT must contain a matching `evaluatedCondition` for each |

Returns `{ valid, pass, payload?, error? }`. Only treat the request as authorized when `pass === true`.

### `useSkyeGate(options)` → `UseSkyeGateResult`

React hook. Same options as `verifyConditions`, plus `enabled?: boolean` to gate the call. Returns `{ status, pass, jwt, error, refetch }` where `status` cycles through `'idle' → 'verifying' → 'pass' | 'fail' | 'error'`.

### `<GatedContent />`

Declarative wrapper. Same options as the hook. Renders `children` only when the gate passes; renders `fallback` otherwise; renders `loading` while verifying. Optional `onPass(jwt)` callback fires once when the gate first passes.

## Condition types

Same vocabulary as the [SkyeGate Pro WordPress plugin](https://skyemeta.com/skyegate/) and [InsumerAPI](https://insumermodel.com/developers/). All four types are supported:

| Type | What it checks |
|---|---|
| `token_balance` | ERC-20 / SPL / native balance ≥ threshold on a chain |
| `nft_ownership` | ERC-721 / ERC-1155 / SPL NFT ownership |
| `eas_attestation` | Ethereum Attestation Service templates (Coinbase Verified, Gitcoin Passport, …) |
| `farcaster_id` | Wallet linked to a Farcaster identity |

32 chains supported (the same set as SkyeGate Pro). See [skyemeta.com/skyegate](https://skyemeta.com/skyegate/) for the full list.

## How it works

```
your Next.js app
  ↓ verifyConditions(address, conditions, licenseKey)
  ↓
skyemeta.com/api/verify   ← SkyeMeta proxy validates SKYE key + domain
  ↓
api.insumermodel.com      ← signed boolean returned, no balances exposed
  ↓
JWT signed with ECDSA P-256
  ↓ POSTed to your server
  ↓
validateContentToken(jwt) ← jose + JWKS, signature + issuer + expiry + condition match
  ↓
gated content delivered
```

The wallet's actual balances never reach your server or your customers — only the signed yes-or-no on whether the condition was met.

## Security notes

- **License key exposure.** `NEXT_PUBLIC_SKYE_LICENSE_KEY` is a public env var by design. Domain locking on the proxy prevents reuse from other origins. If your key leaks, rotate it from `/account/` on skyemeta.com.
- **Replay protection.** Pass `expectedConditions` to `validateContentToken` to ensure a JWT earned for one route can't unlock another.
- **JWT freshness.** JWTs expire after 30 minutes (set by InsumerAPI). Your route gets a fresh one on each verification.
- **CORS.** The proxy is open by default — domain locking happens at the SKYE-key validation layer, not via origin headers.

## Comparison with `@skyemeta/skyegate` for WordPress

| | WordPress plugin | This SDK |
|---|---|---|
| Distribution | `downloads/skyegate-wordpress.zip` from skyemeta.com | npm |
| Stack | PHP + jQuery + minified vanilla JS | TypeScript / React |
| Wallet connect | Bundled (multi-wallet, EIP-6963, Phantom + MetaMask + Coinbase) | Bring your own (wagmi, RainbowKit, etc.) |
| License key | Same SKYE key | Same SKYE key |
| Conditions | All 4 types, up to 10 stacked | All 4 types, up to 10 stacked |
| Source | Closed (proprietary plugin) | Open (MIT) |

One license. Pick the channel that matches your stack.

## License

MIT
