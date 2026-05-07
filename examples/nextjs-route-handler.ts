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
  let body: { jwt?: string };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  if (!body.jwt) {
    return Response.json({ error: 'Missing jwt' }, { status: 400 });
  }

  const result = await validateContentToken(body.jwt, {
    // Replay protection — the JWT must have been earned for *this* condition.
    expectedConditions: [{ type: 'farcaster_id' }],
  });

  if (!result.pass) {
    return Response.json({ error: result.error ?? 'Not authorized' }, { status: 403 });
  }

  return Response.json({
    secret:
      'This response was never in the page source. Your wallet unlocked it after a server-side, ECDSA-signed verification.',
  });
}
