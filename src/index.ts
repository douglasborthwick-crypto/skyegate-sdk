/**
 * @skyemeta/skyegate — condition-based content gating for Vercel / Next.js.
 *
 * Talks to skyemeta.com/api/verify with a SKYE license key, asks InsumerAPI
 * (via the SkyeMeta proxy) whether a wallet meets a set of conditions, and
 * returns a signed JWT proving the result. Server endpoints validate the JWT
 * via JWKS before serving gated content.
 *
 * Bring your own wallet stack — wagmi, RainbowKit, ConnectKit, Privy, etc.
 * This SDK only provides the gating layer.
 *
 * Companion to the SkyeGate Pro WordPress plugin: same SKYE license key,
 * same conditions, same proxy. One license, two stacks.
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
  /** Minimum balance for `token_balance`. Decimals applied per-token. */
  threshold?: number;
  /** Decimals for `token_balance` (default 18 for EVM, 9 for Solana, 6 for USDC etc.). */
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
  /** Your SKYE license key (`SKYE_xxx...`). Provision one at skyemeta.com/skyegate/. */
  licenseKey: string;
  /** `"evm"` (default) or `"solana"`. Picks which body field carries the address. */
  walletType?: 'evm' | 'solana';
  /** Override the verification endpoint. Defaults to the production proxy. */
  endpoint?: string;
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

const DEFAULT_VERIFY_ENDPOINT = 'https://skyemeta.com/api/verify';
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
 * const result = await verifyConditions({
 *   address: walletAddress,
 *   conditions: [{
 *     type: 'token_balance',
 *     contractAddress: 'native',
 *     chainId: 1,
 *     threshold: 0.01,
 *   }],
 *   licenseKey: process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!,
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
    conditions: params.conditions,
    format: 'jwt',
  };
  body[walletField] = params.address;

  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SkyeGate-Key': params.licenseKey,
      },
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
    if (signed[key] !== expected[key]) return false;
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
