// Cookie-based password gate for the SAMPLE dashboard site.
// Same pattern as worker.js (the live P3575 gate) with its own cookie,
// sample branding, and a noindex header on everything served.
const DEFAULT_PASSWORD = "ason";
const COOKIE = "sample_auth";

async function tokenFor(pw) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("sample|" + pw));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

// Serve a static asset: HTML revalidates on every load (redeploys show
// immediately), and every response carries X-Robots-Tag so the sample
// never lands in a search index.
async function serveAsset(request, env) {
  const res = await env.ASSETS.fetch(request);
  const h = new Headers(res.headers);
  h.set("X-Robots-Tag", "noindex, nofollow");
  const ct = res.headers.get("Content-Type") || "";
  if (ct.includes("text/html")) h.set("Cache-Control", "no-cache");
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

function loginPage(msg) {
  const err = msg ? `<p class="err">${msg}</p>` : "";
  const html = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Ason Group — Sign in</title>
<style>
  :root{color-scheme:dark}
  body{margin:0;height:100vh;display:grid;place-items:center;background:#0b0c0e;
       font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e8e8ea}
  form{width:min(90vw,340px);padding:34px 30px;background:#141619;border:1px solid #26292e;border-radius:14px}
  h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;color:#c8a34a;margin:0 0 4px}
  p.sub{margin:0 0 22px;font-size:13px;color:#9aa0a6}
  input{width:100%;box-sizing:border-box;padding:12px 14px;margin-bottom:14px;background:#0b0c0e;
        border:1px solid #33373d;border-radius:8px;color:#fff;font-size:15px}
  button{width:100%;padding:12px;border:0;border-radius:8px;background:#c8a34a;color:#0b0c0e;
         font-size:15px;font-weight:600;cursor:pointer}
  p.err{color:#e5736b;font-size:13px;margin:0 0 14px}
</style></head><body>
<form method="POST" action="/__auth">
  <h1>Sydney Industrial Precinct</h1>
  <p class="sub">Sample Traffic Modelling Dashboards — protected</p>
  ${err}
  <input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password">
  <button type="submit">View dashboard</button>
</form></body></html>`;
  return new Response(html, {
    status: 401,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Robots-Tag": "noindex, nofollow",
    },
  });
}

export default {
  async fetch(request, env) {
    const expected = (env && env.SITE_PASSWORD) || DEFAULT_PASSWORD;
    const token = await tokenFor(expected);
    const url = new URL(request.url);

    // Login submission
    if (request.method === "POST" && url.pathname === "/__auth") {
      const form = await request.formData();
      if ((form.get("password") || "") === expected) {
        return new Response(null, {
          status: 303,
          headers: {
            "Location": "/",
            "Set-Cookie": `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`,
          },
        });
      }
      return loginPage("Incorrect password. Try again.");
    }

    // Authorised by cookie?
    const cookies = request.headers.get("Cookie") || "";
    if (cookies.split(/;\s*/).includes(`${COOKIE}=${token}`)) {
      return serveAsset(request, env);
    }

    // Fallback: HTTP Basic Auth (curl / programmatic)
    const auth = request.headers.get("Authorization") || "";
    if (auth.startsWith("Basic ")) {
      try {
        const decoded = atob(auth.slice(6));
        if (decoded.slice(decoded.indexOf(":") + 1) === expected) {
          return serveAsset(request, env);
        }
      } catch (e) { /* fall through */ }
    }

    return loginPage();
  },
};
