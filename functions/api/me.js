/**
 * Pages Function: GET /api/me
 * Reads the CF_Authorization cookie (HttpOnly, set by Cloudflare Access),
 * decodes the JWT to extract the user's email, then proxies
 * to the worker API to look up the full user record.
 */
export async function onRequest(context) {
  const headers = { 'Content-Type': 'application/json' };

  try {
    const cookie = context.request.headers.get('Cookie') || '';
    const match = cookie.match(/CF_Authorization=([^;]+)/);

    if (!match) {
      return new Response(JSON.stringify({ error: 'No CF_Authorization cookie found' }), { status: 401, headers });
    }

    // Decode JWT payload (middle segment)
    const payload = JSON.parse(atob(match[1].split('.')[1]));
    const email = (payload.email || '').trim().toLowerCase();

    if (!email) {
      return new Response(JSON.stringify({ error: 'No email in JWT payload' }), { status: 401, headers });
    }

    // Proxy to the worker
    const workerResp = await fetch(
      `https://bondwood-api.bondwood.workers.dev/api/me?email=${encodeURIComponent(email)}`
    );
    const data = await workerResp.json();

    return new Response(JSON.stringify(data), {
      status: workerResp.status,
      headers
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Failed to decode auth token', detail: e.message }), { status: 500, headers });
  }
}
