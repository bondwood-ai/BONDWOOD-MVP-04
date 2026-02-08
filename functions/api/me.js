/**
 * Pages Function: GET /api/me
 * Reads the Clerk session cookie (__session or __clerk_db_jwt),
 * decodes the JWT to extract the user's email, then proxies
 * to the worker API to look up the full user record.
 */
export async function onRequest(context) {
  const { request } = context;
  const headers = { 'Content-Type': 'application/json' };

  try {
    const cookieHeader = request.headers.get('Cookie') || '';

    // Try Clerk session cookies
    const token = getCookie(cookieHeader, '__session') || getCookie(cookieHeader, '__clerk_db_jwt');

    if (!token) {
      return new Response(JSON.stringify({ error: 'No session cookie found' }), { status: 401, headers });
    }

    // Decode JWT payload (middle segment)
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));

    // Clerk stores email in different possible locations
    const email = (
      payload.email ||
      payload.email_address ||
      (payload.unsafe_metadata && payload.unsafe_metadata.email) ||
      (payload.public_metadata && payload.public_metadata.email) ||
      ''
    ).trim().toLowerCase();

    if (!email) {
      // Return the payload so we can debug where the email lives
      return new Response(JSON.stringify({
        error: 'No email found in JWT',
        payload_keys: Object.keys(payload),
        payload_preview: payload
      }), { status: 401, headers });
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
    return new Response(JSON.stringify({ error: 'Failed to decode session', detail: e.message }), { status: 500, headers });
  }
}

function getCookie(cookieHeader, name) {
  const cookies = cookieHeader.split(';').map(c => c.trim());
  for (const cookie of cookies) {
    if (cookie.startsWith(name + '=')) {
      return cookie.substring(name.length + 1);
    }
  }
  return null;
}
