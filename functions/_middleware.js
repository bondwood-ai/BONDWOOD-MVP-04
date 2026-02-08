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
  
  // Get session cookie - check both production and development cookie names
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionToken = getCookie(cookieHeader, '__session') || getCookie(cookieHeader, '__clerk_db_jwt');
  const clientUat = getCookie(cookieHeader, '__client_uat');
  
  // If client_uat is 0 or missing, user is not authenticated
  if (!clientUat || clientUat === '0') {
    const redirectUrl = encodeURIComponent(request.url);
    return Response.redirect(`${url.origin}/login?redirect_url=${redirectUrl}`, 302);
  }
  
  // If we have a session token, verify it
  if (sessionToken) {
    const isValid = await verifyClerkJWT(sessionToken, env);
    if (isValid) {
      return next();
    }
  }
  
  // No valid session - redirect to login
  const redirectUrl = encodeURIComponent(request.url);
  return Response.redirect(`${url.origin}/login?redirect_url=${redirectUrl}`, 302);
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

async function verifyClerkJWT(token, env) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return false;
    }
    
    // Check not before
    if (payload.nbf && payload.nbf > now) {
      return false;
    }
    
    return true;
  } catch (e) {
    return false;
  }
}