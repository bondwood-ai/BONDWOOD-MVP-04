export async function onRequest(context) {
  const { request, env } = context;
  const headers = { 'Content-Type': 'application/json' };

  try {
    const cookieHeader = request.headers.get('Cookie') || '';
    const token = getCookie(cookieHeader, '__session') || getCookie(cookieHeader, '__clerk_db_jwt');

    if (!token) {
      return new Response(JSON.stringify({ error: 'No session cookie found' }), { status: 401, headers });
    }

    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    const userId = payload.sub;

    if (!userId) {
      return new Response(JSON.stringify({ error: 'No user ID in JWT' }), { status: 401, headers });
    }

    const clerkKey = env.CLERK_SECRET_KEY;
    if (!clerkKey) {
      return new Response(JSON.stringify({ error: 'CLERK_SECRET_KEY not configured' }), { status: 500, headers });
    }

    // Call Clerk Backend API
    const clerkResp = await fetch(`https://api.clerk.com/v1/users/${userId}`, {
      headers: { 'Authorization': `Bearer ${clerkKey}` }
    });

    // Return full debug info if not OK
    if (!clerkResp.ok) {
      const body = await clerkResp.text();
      return new Response(JSON.stringify({
        error: 'Clerk API error',
        status: clerkResp.status,
        userId,
        clerkResponse: body,
        keyPrefix: clerkKey.substring(0, 12) + '...'
      }), { status: 500, headers });
    }

    const clerkUser = await clerkResp.json();

    const email = (
      clerkUser.email_addresses && clerkUser.email_addresses.length > 0
        ? (clerkUser.email_addresses.find(e => e.id === clerkUser.primary_email_address_id)?.email_address
          || clerkUser.email_addresses[0].email_address)
        : ''
    ).trim().toLowerCase();

    if (!email) {
      return new Response(JSON.stringify({ error: 'No email found for user' }), { status: 404, headers });
    }

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
