// Edge-side HTTP Basic Auth gate for Cloudflare Pages.
// Runs before any static asset is served, so the page HTML is never
// delivered to an unauthenticated client. Any username is accepted;
// only the password is checked. The password is read from the
// SITE_PASSWORD environment variable if set (Cloudflare dashboard ->
// Settings -> Environment variables), otherwise falls back to the
// default below.
const DEFAULT_PASSWORD = "ason";

export async function onRequest(context) {
  const { request, next, env } = context;
  const expected = (env && env.SITE_PASSWORD) || DEFAULT_PASSWORD;

  const header = request.headers.get("Authorization") || "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice(6));           // "user:pass"
      const password = decoded.slice(decoded.indexOf(":") + 1);
      if (password === expected) {
        return next();                                 // authorised -> serve site
      }
    } catch (e) {
      // fall through to challenge
    }
  }

  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Port Kembla Dashboard", charset="UTF-8"',
    },
  });
}
