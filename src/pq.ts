/**
 * Post-quantum companion check for the InsumerAPI JWT (ML-DSA-65, RFC 9964).
 *
 * InsumerAPI returns a sibling `pqJwt` beside `jwt`: a compact JWS with
 * `alg: "ML-DSA-65"` over the same claims, signed under a post-quantum key
 * published in the same JWKS as an RFC 9964 `AKP` entry. It is ADDITIVE; the
 * ES256 `jwt` this package already verifies is unchanged.
 *
 * ML-DSA is not in Web Crypto or jose. Verification uses `@noble/post-quantum`
 * when it is installed (optional peer dependency); when it is not, the status
 * is `unverifiable` with a reason, never a silent pass or a silent failure.
 *
 * Reported, not refused: the companion's status is returned beside the
 * classical result. `refuted` (present and failing) is always treated as a
 * failure. `absent` or `unverifiable` only matter once the caller's own
 * `pqRequiredFrom` date has passed, judged by this process's clock.
 */

export type PqStatus = 'verified' | 'refuted' | 'absent' | 'unverifiable';

export interface PqResult {
  status: PqStatus;
  kid?: string;
  reason?: string;
}

type MlDsa = { verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => boolean };
let mlDsaPromise: Promise<MlDsa | null> | undefined;
async function loadMlDsa(): Promise<MlDsa | null> {
  if (!mlDsaPromise) {
    mlDsaPromise = (async () => {
      try {
        const name = '@noble/post-quantum/ml-dsa.js';
        const mod = (await import(/* @vite-ignore */ name)) as { ml_dsa65?: MlDsa };
        return mod.ml_dsa65 ?? null;
      } catch {
        return null;
      }
    })();
  }
  return mlDsaPromise;
}

function b64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  if (pad === 2) b64 += '==';
  else if (pad === 3) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const pqKeyCache = new Map<string, { at: number; keys: Map<string, Uint8Array> }>();
const PQ_KEY_TTL_MS = 10 * 60 * 1000;

async function fetchPqKey(jwksUrl: string, kid: string): Promise<Uint8Array> {
  const cached = pqKeyCache.get(jwksUrl);
  if (cached && Date.now() - cached.at < PQ_KEY_TTL_MS && cached.keys.has(kid)) {
    return cached.keys.get(kid)!;
  }
  const res = await fetch(jwksUrl);
  if (!res.ok) throw new Error(`JWKS fetch failed: HTTP ${res.status}`);
  const jwks = (await res.json()) as { keys?: Array<Record<string, unknown>> };
  const keys = new Map<string, Uint8Array>();
  for (const k of jwks.keys ?? []) {
    if (k.kty === 'AKP' && k.alg === 'ML-DSA-65' && typeof k.kid === 'string' && typeof k.pub === 'string') {
      keys.set(k.kid, b64urlToBytes(k.pub));
    }
  }
  pqKeyCache.set(jwksUrl, { at: Date.now(), keys });
  const key = keys.get(kid);
  if (!key) throw new Error(`JWKS has no ML-DSA-65 key matching pqKid "${kid}"`);
  return key;
}

/**
 * Verify the companion and bind it to the already-verified ES256 payload.
 * Never throws; every outcome is a status.
 */
export async function verifyPqCompanion(
  pqJwt: string | undefined,
  classicalPayload: Record<string, unknown>,
  jwksUrl: string,
): Promise<PqResult> {
  if (!pqJwt) return { status: 'absent', reason: 'No post-quantum companion on this response' };
  const parts = pqJwt.split('.');
  if (parts.length !== 3) return { status: 'refuted', reason: 'pqJwt is not a 3-segment compact JWS' };
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
  } catch {
    return { status: 'refuted', reason: 'pqJwt header or payload is not valid JSON' };
  }
  const kid = typeof header.kid === 'string' ? header.kid : undefined;
  if (header.alg !== 'ML-DSA-65' || !kid) {
    return { status: 'refuted', kid, reason: `pqJwt header must carry alg ML-DSA-65 and a kid (got ${String(header.alg)})` };
  }
  const mlDsa = await loadMlDsa();
  if (!mlDsa) {
    return { status: 'unverifiable', kid, reason: 'ML-DSA verifier unavailable (install @noble/post-quantum to check the companion)' };
  }
  let publicKey: Uint8Array;
  try {
    publicKey = await fetchPqKey(jwksUrl, kid);
  } catch (err) {
    return { status: 'unverifiable', kid, reason: err instanceof Error ? err.message : String(err) };
  }
  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  let ok = false;
  try {
    ok = mlDsa.verify(b64urlToBytes(parts[2]), signingInput, publicKey);
  } catch (err) {
    return { status: 'refuted', kid, reason: `ML-DSA verification error: ${err instanceof Error ? err.message : String(err)}` };
  }
  if (!ok) return { status: 'refuted', kid, reason: 'pqJwt signature does not verify' };
  for (const claim of ['jti', 'exp', 'pass', 'sub']) {
    if (JSON.stringify(payload[claim]) !== JSON.stringify(classicalPayload[claim])) {
      return { status: 'refuted', kid, reason: `pqJwt claim "${claim}" differs from the ES256 JWT` };
    }
  }
  return { status: 'verified', kid };
}

/** Policy: does this companion status fail the check, given the caller's cutoff? */
export function pqFails(result: PqResult, pqRequiredFrom?: string | Date): boolean {
  if (result.status === 'refuted') return true;
  if (result.status === 'verified') return false;
  if (!pqRequiredFrom) return false;
  const from = new Date(pqRequiredFrom).getTime();
  if (isNaN(from)) {
    throw new Error(`pqRequiredFrom is not a valid date: ${String(pqRequiredFrom)}`);
  }
  return Date.now() >= from;
}
