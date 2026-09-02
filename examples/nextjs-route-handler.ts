/**
 * Next.js App Router route handler — server-side JWT validation.
 *
 * Drop this in `app/api/gated-content/route.ts`. The browser POSTs the JWT
 * (returned by `verifyConditions` or `<GatedContent />` on the client) and
 * this endpoint validates the signature, issuer, expiry, and (optionally) the
 * specific conditions before serving gated content.
 */

import { validateContentToken } from '@skyemeta/skyegate';

export async function POST(req: Request) {
  let body: { jwt?: string; pqJwt?: string };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  if (!body.jwt) {
    return Response.json({ error: 'Missing jwt' }, { status: 400 });
  }

  const result = await validateContentToken(body.jwt, {
    // Cross-condition replay protection: the JWT must have been earned for
    // *this* condition, not for another route. It does not bind the JWT to
    // whoever presents it. See "Wallet ownership" in the README.
    expectedConditions: [{ type: 'farcaster_id' }],
      pqJwt: body.pqJwt, // post-quantum companion; reported as result.pq
});

  if (!result.pass) {
    return Response.json({ error: result.error ?? 'Not authorized' }, { status: 403 });
  }

  return Response.json({
    secret:
      'This response was never in the page source. It arrived after the server ' +
      'verified a signed InsumerAPI attestation that this address meets the condition.',
  });
}
