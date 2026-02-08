/**
 * Pages Function: GET /api/me
 * Reads Clerk session JWT to get user ID, then calls Clerk Backend API
 * to get email, then proxies to worker to get employee details.
 */
export async function onRequest(context) {
  const { request, env } = context;
  const headers = { 'Content-Type': 'application/json' };

  try {
    const cookieHeader = request.headers.get('Cookie') || '';
    const token = getCookie(cookieHeader, '__session') || getCookie(cookieHeader, '__clerk_db_jwt');

    if (!token) {
      return new Response(JSON.stringify({ error: 'No session cookie found' }), { status: 401, headers });
    }

    // Decode JWT to get Clerk user ID (sub)
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    const userId = payload.sub;

    if (!userId) {
      return new Response(JSON.stringify({ error: 'No user ID in JWT' }), { status: 401, headers });
    }

    // Call Clerk Backend API to get user details
    const clerkKey = env.CLERK_SECRET_KEY;
    if (!clerkKey) {
      return new Response(JSON.stringify({ error: 'CLERK_SECRET_KEY not configured' }), { status: 500, headers });
    }

    const clerkResp = await fetch(`https://api.clerk.com/v1/users/${userId}`, {
      headers: { 'Authorization': `Bearer ${clerkKey}` }
    });

    if (!clerkResp.ok) {
      return new Response(JSON.stringify({ error: 'Clerk API error', status: clerkResp.status }), { status: 500, headers });
    }

    const clerkUser = await clerkResp.json();

    // Get primary email from Clerk user
    const email = (
      (clerkUser.email_addresses && clerkUser.email_addresses.length > 0
        ? clerkUser.email_addresses.find(e => e.id === clerkUser.primary_email_address_id)?.email_address
          || clerkUser.email_addresses[0].email_address
        : '')
    ).trim().toLowerCase();

    if (!email) {
      return new Response(JSON.stringify({ error: 'No email found for user' }), { status: 404, headers });
    }

    // Proxy to worker to get employee record
    const workerResp = await fetch(
      `https://bondwood-api.bondwood.workers.dev/api/me?email=${encodeURIComponent(email)}`
    );
    const data = await workerResp.json();

    return new Response(JSON.stringify(data), {
      status: workerResp.status,
      headers
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Failed to process session', detail: e.message }), { status: 500, headers });
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
