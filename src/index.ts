/**
 * @skyemeta/skyegate — condition-based content gating for Vercel / Next.js.
 *
 * SkyeGate is a SkyeMeta product. The wallet verification engine it relies on
 * — signed boolean attestations over wallet conditions — is InsumerAPI, an
 * independent product of InsumerModel. SkyeGate is powered by InsumerAPI;
 * they are separate companies.
 *
 * The SDK talks to the SkyeMeta proxy (skyemeta.com/api/verify) with a SKYE
 * license key. The proxy authenticates the key, forwards the request to
 * InsumerAPI, and returns a signed JWT. Server endpoints validate the JWT via
 * JWKS before serving gated content.
 *
 * Trust model: every result is cryptographically signed (ECDSA P-256 + JWKS),
 * independently verifiable by any third party. Trust the math, not a company —
 * including us.
 *
 * Bring your own wallet stack — wagmi, RainbowKit, ConnectKit, Privy, etc.
 * This SDK only provides the gating layer.
 *
 * Companion to the SkyeGate WordPress plugin: same SKYE license key, same
 * conditions, same proxy. One license, two stacks.
 */

import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';

// ── Public types ──────────────────────────────────────────────────────────

/** A SkyeGate condition — same shape the WordPress Pro plugin sends. */
export interface Condition {
  /** Condition kind. */
  type: 'token_balance' | 'nft_ownership' | 'eas_attestation' | 'farcaster_id';
  /** Token / NFT contract address, or `"native"` for chain-native tokens. */
  contractAddress?: string;
  /** Numeric chain ID for EVM chains; `"solana"` for Solana; `"xrpl"` for XRP Ledger. */
  chainId?: number | string;
  /**
   * Minimum balance for `token_balance`. Prefer a decimal string (`'100'`) —
   * it keeps full precision and is the form v2 signing keys require; a number
   * is accepted and converted to its decimal-string form before sending.
   */
  threshold?: number | string;
  /** Decimals for `token_balance`. Token-specific — check the token's documentation. */
  decimals?: number;
  /** EAS template name, e.g. `"coinbase_verified_account"`, `"gitcoin_passport_active"`. */
  template?: string;
  /** XRPL trust line currency code (hex). */
  currency?: string;
  /** Free-form label echoed back in the attestation result. */
  label?: string;
}

export interface VerifyConditionsParams {
  /** Wallet address (EVM hex or Solana base58). */
  address: string;
  /** One or more conditions; pass=true requires every condition to be met. */
  conditions: Condition[];
  /** Your SKYE license key (format: `SKYE-XXXX-XXXX-XXXX`). Provision one at skyemeta.com/skyegate/. */
  licenseKey: string;
  /** `"evm"` (default) or `"solana"`. Picks which body field carries the address. */
  walletType?: 'evm' | 'solana';
  /** Override the verification endpoint. Defaults to the production proxy. */
  endpoint?: string;
  /**
   * Domain to claim for license-binding. Defaults to `window.location.hostname`
   * in browsers; required for SSR / Node.js calls. Localhost, `*.vercel.app`,
   * and `*.local` are treated as dev/preview and never bind the license.
   */
  domain?: string;
  /**
   * Wallet ownership proof token from {@link proveWalletOwnership}. Proves the
   * person presenting the address actually controls it — without it, the
   * attestation only says the address meets the conditions. EVM wallets only.
   */
  walletProof?: string;
}

export interface VerifyConditionsResult {
  /** True only if every condition was met by the wallet. */
  pass: boolean;
  /** Signed JWT proving the result. Pass to {@link validateContentToken} on the server. */
  jwt: string | null;
  /** Full InsumerAPI response envelope, for advanced inspection. */
  raw: unknown;
  /** Populated when the proxy or upstream returned a non-2xx or `pass:false`. */
  error?: string;
}

export interface ValidateContentTokenOptions {
  /** Override the JWKS endpoint. Defaults to InsumerAPI's public JWKS. */
  jwksUrl?: string;
  /** Expected `iss` claim. Defaults to InsumerAPI. */
  issuer?: string;
  /**
   * Optional replay protection: ensure the signed conditions in the JWT match
   * the conditions you require for this route. Each expected condition must
   * find a matching `evaluatedCondition` in the JWT's `results` array.
   */
  expectedConditions?: Condition[];
}

export interface ValidateContentTokenResult {
  /** True if the JWT signature, issuer, and expiry all check out. */
  valid: boolean;
  /** True only if `valid` *and* the verification passed *and* (if requested) conditions match. */
  pass: boolean;
  /** Decoded JWT payload (only present when `valid` is true). */
  payload?: JWTPayload & { pass?: boolean; results?: unknown[] };
  /** Reason for failure when `valid` or `pass` is false. */
  error?: string;
}

// ── Constants ─────────────────────────────────────────────────────────────

// ── Decimal-string thresholds ─────────────────────────────────────────────
// v2 InsumerAPI signing keys require token_balance thresholds as decimal
// strings (a JSON number has already lost precision by parse time). Numbers
// are still accepted here and converted before sending; the exponent-free
// form matches the upstream grammar ^\d+(\.\d+)?$.

function numberToDecimalString(n: number): string | null {
  const s = String(n);
  const m = s.match(/^(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/);
  if (!m) return null; // negative, NaN, Infinity — not representable upstream
  const [, int, frac = '', expStr] = m;
  if (expStr === undefined) return s;
  const digits = int + frac;
  const exp = parseInt(expStr, 10) - frac.length;
  if (exp >= 0) return digits + '0'.repeat(exp);
  const point = digits.length + exp;
  return point <= 0
    ? '0.' + '0'.repeat(-point) + digits
    : digits.slice(0, point) + '.' + digits.slice(point);
}

// Canonical form for era-tolerant equality: a v1-signed JWT echoes thresholds
// as numbers, a v2-signed JWT as canonical decimal strings ("00.50" → "0.5").
function canonicalThreshold(v: unknown): string | null {
  let s: string | null;
  if (typeof v === 'number' && Number.isFinite(v)) {
    s = numberToDecimalString(v);
    if (s === null) return null;
  } else if (typeof v === 'string') {
    s = v.trim();
    if (/[eE]/.test(s)) {
      const n = Number(s);
      if (!Number.isFinite(n)) return null;
      s = numberToDecimalString(n);
      if (s === null) return null;
    }
    if (!/^\d+(\.\d+)?$/.test(s)) return null;
  } else {
    return null;
  }
  const [int, frac = ''] = s.split('.');
  const i = int.replace(/^0+(?=\d)/, '');
  const f = frac.replace(/0+$/, '');
  return f ? i + '.' + f : i;
}

function withStringThresholds(conditions: Condition[]): Condition[] {
  return conditions.map((c) => {
    if (typeof c.threshold === 'number' && Number.isFinite(c.threshold)) {
      const s = numberToDecimalString(c.threshold);
      if (s !== null) return { ...c, threshold: s };
    }
    return c;
  });
}

const DEFAULT_VERIFY_ENDPOINT = 'https://skyemeta.com/api/verify';
const DEFAULT_PROOF_ENDPOINT = 'https://skyemeta.com/api/wallet-proof';
const DEFAULT_JWKS_URL = 'https://api.insumermodel.com/.well-known/jwks.json';
const DEFAULT_ISSUER = 'https://api.insumermodel.com';

// ── verifyConditions ─────────────────────────────────────────────────────

/**
 * Ask the SkyeMeta proxy whether a wallet meets one or more conditions.
 *
 * The proxy authenticates your SKYE license key (per-domain, rate-limited),
 * forwards the request to InsumerAPI, and returns the signed result. On pass,
 * use the returned JWT as a bearer token to fetch gated content from your
 * server, where {@link validateContentToken} verifies it before responding.
 *
 * @example
 * ```ts
 * import { verifyConditions } from '@skyemeta/skyegate';
 *
 * // Licensed EVM calls require a wallet-ownership proof (403 without it):
 * const proof = await proveWalletOwnership({ address: walletAddress, provider: window.ethereum });
 *
 * const result = await verifyConditions({
 *   address: walletAddress,
 *   conditions: [{
 *     type: 'token_balance',
 *     contractAddress: 'native',
 *     chainId: 1,
 *     threshold: '0.01',
 *   }],
 *   licenseKey: process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!,
 *   walletProof: proof.proofToken!,
 * });
 *
 * if (result.pass && result.jwt) {
 *   // POST result.jwt to your /api/gated-content endpoint
 * }
 * ```
 */
export async function verifyConditions(
  params: VerifyConditionsParams
): Promise<VerifyConditionsResult> {
  const endpoint = params.endpoint ?? DEFAULT_VERIFY_ENDPOINT;
  const walletField = params.walletType === 'solana' ? 'solanaWallet' : 'wallet';

  const body: Record<string, unknown> = {
    conditions: withStringThresholds(params.conditions),
    format: 'jwt',
  };
  body[walletField] = params.address;
  if (params.walletProof) body.wallet_proof = params.walletProof;

  const domain =
    params.domain ??
    (typeof window !== 'undefined' && window.location ? window.location.hostname : undefined);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-SkyeGate-License': params.licenseKey,
  };
  if (domain) headers['X-SkyeGate-Domain'] = domain;

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  } catch (err) {
    return {
      pass: false,
      jwt: null,
      raw: null,
      error: err instanceof Error ? err.message : 'Network error reaching SkyeMeta proxy',
    };
  }

  let data: any;
  try {
    data = await response.json();
  } catch {
    return {
      pass: false,
      jwt: null,
      raw: null,
      error: `Invalid JSON from proxy (HTTP ${response.status})`,
    };
  }

  if (!response.ok) {
    return {
      pass: false,
      jwt: null,
      raw: data,
      error: data?.error ?? `HTTP ${response.status}`,
    };
  }

  const attestation = data?.data?.attestation;
  const jwt = data?.data?.jwt ?? null;
  const pass = attestation?.pass === true;

  return { pass, jwt, raw: data };
}

// ── proveWalletOwnership ─────────────────────────────────────────────────

/** Minimal EIP-1193 provider surface — what `window.ethereum` exposes. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

export interface ProveWalletOwnershipParams {
  /** The EVM wallet address to prove control of. */
  address: string;
  /**
   * An EIP-1193 provider (e.g. `window.ethereum`) used to request the
   * signature. Ignored when `signMessage` is supplied.
   */
  provider?: Eip1193Provider;
  /**
   * Bring-your-own signer: given the challenge message, return the signature.
   * Use this with wagmi (`signMessageAsync({ message })`), viem wallet
   * clients, Privy, etc.
   */
  signMessage?: (message: string) => Promise<string>;
  /** Domain to stamp into the challenge. Defaults to `window.location.hostname`. */
  domain?: string;
  /** Override the proof endpoint. Defaults to the production proxy. */
  proofEndpoint?: string;
}

export interface ProveWalletOwnershipResult {
  /** Pass to {@link verifyConditions} as `walletProof`. Null on failure. */
  proofToken: string | null;
  /** Seconds the token stays valid; one signature covers the whole visit. */
  expiresInSec?: number;
  /** Populated when the challenge, signature, or verification failed. */
  error?: string;
}

/**
 * Prove the person present controls the wallet, not just that they typed its
 * address. Requests a one-time challenge from the SkyeMeta proof endpoint,
 * has the wallet sign it (EIP-191 `personal_sign` — free, gasless, no
 * transaction), and exchanges the signature for a short-lived proof token.
 *
 * The signature goes from the member's browser to the proof endpoint
 * directly — it never passes through your server, and the verification stays
 * an air gap: your server still only sees the address and the signed boolean.
 * Smart-contract wallets (e.g. Coinbase Smart Wallet passkeys) are verified
 * on-chain via EIP-1271/6492.
 *
 * The token is session-scoped: prove once when the wallet connects, then pass
 * the token to every {@link verifyConditions} call for the rest of the visit.
 *
 * @example
 * ```ts
 * import { proveWalletOwnership, verifyConditions } from '@skyemeta/skyegate';
 *
 * const proof = await proveWalletOwnership({
 *   address: walletAddress,
 *   provider: window.ethereum,
 * });
 * if (!proof.proofToken) throw new Error(proof.error);
 *
 * const result = await verifyConditions({
 *   address: walletAddress,
 *   conditions,
 *   licenseKey: process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!,
 *   walletProof: proof.proofToken,
 * });
 * ```
 */
export async function proveWalletOwnership(
  params: ProveWalletOwnershipParams
): Promise<ProveWalletOwnershipResult> {
  const endpoint = params.proofEndpoint ?? DEFAULT_PROOF_ENDPOINT;
  const domain =
    params.domain ??
    (typeof window !== 'undefined' && window.location ? window.location.hostname : undefined);

  if (!params.signMessage && !params.provider) {
    return { proofToken: null, error: 'Pass a provider (window.ethereum) or a signMessage callback' };
  }

  let challenge: { challengeId?: string; message?: string; error?: string };
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'challenge', wallet: params.address, domain }),
    });
    challenge = await res.json();
    if (!res.ok || !challenge.challengeId || !challenge.message) {
      return { proofToken: null, error: challenge.error ?? `Challenge failed (HTTP ${res.status})` };
    }
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Network error reaching proof endpoint',
    };
  }

  let signature: string;
  try {
    if (params.signMessage) {
      signature = await params.signMessage(challenge.message);
    } else {
      // personal_sign takes the message hex-encoded; wallets render the UTF-8.
      const hex =
        '0x' +
        Array.from(new TextEncoder().encode(challenge.message))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      signature = (await params.provider!.request({
        method: 'personal_sign',
        params: [hex, params.address],
      })) as string;
    }
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Signature request was rejected',
    };
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        action: 'prove',
        challengeId: challenge.challengeId,
        wallet: params.address,
        signature,
      }),
    });
    const data = await res.json();
    if (!res.ok || !data.proofToken) {
      return { proofToken: null, error: data.error ?? `Proof failed (HTTP ${res.status})` };
    }
    return { proofToken: data.proofToken, expiresInSec: data.expiresInSec };
  } catch (err) {
    return {
      proofToken: null,
      error: err instanceof Error ? err.message : 'Network error reaching proof endpoint',
    };
  }
}

// ── validateContentToken ─────────────────────────────────────────────────

const jwksByUrl = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: string) {
  let jwks = jwksByUrl.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksByUrl.set(url, jwks);
  }
  return jwks;
}

function compareCondition(signed: Record<string, unknown>, expected: Condition): boolean {
  for (const key of Object.keys(expected) as (keyof Condition)[]) {
    if (key === 'threshold') {
      // Era-tolerant: a v1-signed JWT echoes token_balance thresholds as
      // numbers, a v2-signed JWT as canonical decimal strings.
      const a = canonicalThreshold(signed[key]);
      if (a === null || a !== canonicalThreshold(expected[key])) return false;
    } else if (signed[key] !== expected[key]) {
      return false;
    }
  }
  return true;
}

/**
 * Validate a JWT returned by {@link verifyConditions} on your server.
 *
 * Verifies the ECDSA P-256 signature against InsumerAPI's JWKS, checks the
 * issuer + expiry, and (optionally) confirms that the signed conditions match
 * what your route requires — preventing a JWT earned for one condition set
 * from being replayed against a different one.
 *
 * @example Next.js route handler
 * ```ts
 * import { validateContentToken } from '@skyemeta/skyegate';
 *
 * export async function POST(req: Request) {
 *   const { jwt } = await req.json();
 *   const result = await validateContentToken(jwt, {
 *     expectedConditions: [{ type: 'farcaster_id' }],
 *   });
 *   if (!result.pass) {
 *     return Response.json({ error: result.error }, { status: 403 });
 *   }
 *   return Response.json({ secret: 'gated content here' });
 * }
 * ```
 */
export async function validateContentToken(
  jwt: string,
  options: ValidateContentTokenOptions = {}
): Promise<ValidateContentTokenResult> {
  if (!jwt || typeof jwt !== 'string') {
    return { valid: false, pass: false, error: 'Missing or invalid JWT' };
  }

  const jwksUrl = options.jwksUrl ?? DEFAULT_JWKS_URL;
  const issuer = options.issuer ?? DEFAULT_ISSUER;

  let payload: JWTPayload & { pass?: boolean; results?: unknown[] };
  try {
    const verified = await jwtVerify(jwt, getJwks(jwksUrl), { issuer });
    payload = verified.payload as typeof payload;
  } catch (err) {
    return {
      valid: false,
      pass: false,
      error: err instanceof Error ? err.message : 'JWT verification failed',
    };
  }

  if (payload.pass !== true) {
    return { valid: true, pass: false, payload, error: 'Verification did not pass' };
  }

  if (options.expectedConditions && options.expectedConditions.length > 0) {
    const signed = Array.isArray(payload.results) ? (payload.results as any[]) : [];
    const allMatched = options.expectedConditions.every((expected) =>
      signed.some(
        (r) =>
          r &&
          typeof r === 'object' &&
          r.evaluatedCondition &&
          compareCondition(r.evaluatedCondition, expected)
      )
    );
    if (!allMatched) {
      return {
        valid: true,
        pass: false,
        payload,
        error: 'Signed conditions do not match expected conditions',
      };
    }
  }

  return { valid: true, pass: true, payload };
}
