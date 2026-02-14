// Clerk Auth Middleware for Cloudflare Pages
// Protects all routes except /login and /sso-callback

export async function onRequest(context) {
  const { request, next, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  
  // Public paths - no auth required
  const publicPaths = [
    '/login',
    '/sso-callback',
  ];
  
  // Check if this is a public path
  const isPublicPath = publicPaths.some(p => path === p || path.startsWith(p + '/'));
  
  if (isPublicPath) {
    return next();
  }
  
  // Get session cookies
  const cookieHeader = request.headers.get('Cookie') || '';
  const clientUat = getCookie(cookieHeader, '__client_uat');
  
  // __client_uat is Clerk's source of truth for authentication state.
  // If it's missing or "0", the user has never authenticated or has signed out.
  if (!clientUat || clientUat === '0') {
    const redirectUrl = encodeURIComponent(request.url);
    return Response.redirect(`${url.origin}/login?redirect_url=${redirectUrl}`, 302);
  }
  
  // __client_uat exists and is non-zero — user has an active Clerk session.
  // The __session JWT may be expired (it's short-lived, ~60s), but that's
  // normal. Clerk's frontend JS refreshes it automatically on page load.
  // Redirecting to /login on an expired JWT causes a visible flash because
  // the login page immediately detects the valid session and bounces back.
  return next();
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
