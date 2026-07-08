// Workers Static Assets entry with an HTTP Basic Auth gate in front of every
// asset. `run_worker_first: true` (see wrangler.jsonc) makes this run before
// asset matching, so nothing is served until the password checks out. Any
// username is accepted; only the password is validated. The password is read
// from the SITE_PASSWORD environment variable if set, else the default below.
const DEFAULT_PASSWORD = "ason";

export default {
  async fetch(request, env) {
    const expected = (env && env.SITE_PASSWORD) || DEFAULT_PASSWORD;

    const header = request.headers.get("Authorization") || "";
    if (header.startsWith("Basic ")) {
      try {
        const decoded = atob(header.slice(6));            // "user:pass"
        const password = decoded.slice(decoded.indexOf(":") + 1);
        if (password === expected) {
          return env.ASSETS.fetch(request);               // authorised -> serve asset
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
  },
};
