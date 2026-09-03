/**
 * IOC Distribution Portal — frontend host + API proxy (App Service).
 *
 * Design rules honoured:
 *  - Zero npm dependencies (nothing to patch for CVEs; Node 22 LTS built-ins only).
 *  - No secrets in code: the Function App base URL, function key and the
 *    Entra group->role map all come from App Settings (key/secret values as
 *    Key Vault references).
 *  - Users NEVER reach the Function App directly: this server is the only
 *    caller (Function App has public access disabled + requires the key),
 *    and it injects the verified identity as x-portal-* headers.
 *  - Identity comes from App Service Authentication (Easy Auth) which sets
 *    the x-ms-client-principal header after Entra ID sign-in. Roles are
 *    derived from the token's group claims via ROLE_GROUP_MAP
 *    ("ioc-admin=<groupId>;ioc-operator=<groupId>") — two groups.
 *  - WHICH TABS/DATA each role can see is NOT decided here — it lives in
 *    the "permissions" block of portal-config.json (see shared/config.py
 *    and index.html's applyRoleGates()). This file only resolves identity
 *    and role NAMES; visibility is entirely config-driven.
 */
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8080;
const API_BASE = (process.env.FUNCTION_APP_BASE_URL || "").replace(/\/+$/, "");
const API_KEY = process.env.FUNCTION_APP_KEY || "";
const PUBLIC_DIR = path.join(__dirname, "public");

const ROLE_GROUP_MAP = {};
for (const pair of (process.env.ROLE_GROUP_MAP || "").split(";")) {
  const [role, gid] = pair.split("=");
  if (role && gid) ROLE_GROUP_MAP[gid.trim()] = role.trim();
}

/* ---- identity from Easy Auth ------------------------------------------- */
function identity(req) {
  const header = req.headers["x-ms-client-principal"];
  if (!header) return null;
  try {
    const p = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    const claims = p.claims || [];
    const claim = (t) => (claims.find((c) => c.typ === t) || {}).val || "";
    const name =
      claim("preferred_username") || claim("upn") ||
      claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn") ||
      claim("name") || "unknown";
    const oid = claim("oid") ||
      claim("http://schemas.microsoft.com/identity/claims/objectidentifier");
    const roles = [...new Set(
      claims.filter((c) => c.typ === "groups" || c.typ.endsWith("/claims/groups"))
            .map((c) => ROLE_GROUP_MAP[c.val])
            .filter(Boolean))];
    return { name, oid, roles };
  } catch {
    return null;
  }
}

/* ---- helpers ------------------------------------------------------------ */
function send(res, status, body, type = "application/json") {
  res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store" });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

/* ---- open-redirect guard --------------------------------------------------
   No code path in this app currently builds a redirect target from
   user-controlled input (confirmed by audit — the only navigation target
   anywhere is the hardcoded "/.auth/logout?post_logout_redirect_uri=/" in
   index.html). This function exists proactively: if a future feature ever
   needs a "return to this page" redirect parameter, route it through this
   first rather than trusting it directly. Rejects anything that isn't a
   same-origin relative path — including scheme-relative ("//evil.com"),
   backslash-based ("\evil.com", "/\evil.com" — some parsers/browsers treat
   a backslash as equivalent to a forward slash, which is exactly how a
   naive startsWith("/") check gets bypassed), and any "scheme:" prefix. */
function safeRelativeRedirect(candidate, fallback = "/") {
  if (typeof candidate !== "string" || !candidate) return fallback;
  if (candidate.includes("\\")) return fallback;
  if (!candidate.startsWith("/") || candidate.startsWith("//")) return fallback;
  if (/^[a-z][a-z0-9+.-]*:/i.test(candidate)) return fallback;
  return candidate;
}

function serveStatic(res, file) {
  const full = path.join(PUBLIC_DIR, path.normalize(file).replace(/^(\.\.[/\\])+/, ""));
  if (!full.startsWith(PUBLIC_DIR)) return send(res, 403, { error: "Forbidden" });
  fs.readFile(full, (err, data) => {
    if (err) return send(res, 404, { error: "Not found" });
    const type = full.endsWith(".html") ? "text/html; charset=utf-8"
      : full.endsWith(".js") ? "text/javascript" : "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(data);
  });
}

/* ---- rate limiting -------------------------------------------------------
   In-memory, per-identity limiter for /api/* traffic. Keyed by the
   authenticated user's object ID (user.oid), not IP — IP is unreliable
   behind App Service's own proxying, and every caller reaching this check
   is already authenticated by the time it runs, so identity is the more
   meaningful key.

   State is per-process: if this Web App ever scales to more than one
   instance, the effective limit becomes (this limit x instance count),
   not a strict global cap. Acceptable for a first pass; a platform-level
   limiter (Front Door / APIM) would be needed for a hard global guarantee.
   Documented here rather than treated as a silent gap. */
const RATE_LIMIT_WINDOW_MS = 60_000;   // 1 minute window
const RATE_LIMIT_MAX = 60;             // max requests per identity per window
const _rateBuckets = new Map();        // oid -> { count, windowStart }

function isRateLimited(oid) {
  if (!oid) return false; // unauthenticated requests are already rejected
                           // with 401 before this is ever called — this
                           // guard is defensive, not a real bypass path
  const now = Date.now();
  const bucket = _rateBuckets.get(oid);
  if (!bucket || now - bucket.windowStart >= RATE_LIMIT_WINDOW_MS) {
    _rateBuckets.set(oid, { count: 1, windowStart: now });
    return false;
  }
  bucket.count += 1;
  return bucket.count > RATE_LIMIT_MAX;
}

// Periodic cleanup so _rateBuckets doesn't grow unbounded over a
// long-running process — stale buckets (older than 2 windows) are
// dropped every window. .unref() so this timer never keeps the process
// alive on its own.
setInterval(() => {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS * 2;
  for (const [oid, bucket] of _rateBuckets) {
    if (bucket.windowStart < cutoff) _rateBuckets.delete(oid);
  }
}, RATE_LIMIT_WINDOW_MS).unref();

/* ---- API proxy ---------------------------------------------------------- */
async function proxy(req, res, user) {
  if (!API_BASE) return send(res, 500, { error: "FUNCTION_APP_BASE_URL is not configured." });
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const body = Buffer.concat(chunks);

  const headers = {
    "Content-Type": req.headers["content-type"] || "application/json",
    // never forward client-supplied identity headers — set fresh, verified ones
    "x-portal-user": user.name,
    "x-portal-oid": user.oid || "",
    "x-portal-roles": user.roles.join(","),
  };
  if (API_KEY) headers["x-functions-key"] = API_KEY;

  try {
    const upstream = await fetch(API_BASE + req.url, {
      method: req.method,
      headers,
      body: ["GET", "HEAD"].includes(req.method) ? undefined : body,
    });
    const buf = Buffer.from(await upstream.arrayBuffer());
    const out = { "Content-Type": upstream.headers.get("content-type") || "application/json" };
    const disp = upstream.headers.get("content-disposition");
    if (disp) out["Content-Disposition"] = disp;
    res.writeHead(upstream.status, out);
    res.end(buf);
  } catch (e) {
    send(res, 502, { error: "Backend unreachable: " + e.message });
  }
}

/* ---- server ------------------------------------------------------------- */
http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];

  if (url === "/health") return send(res, 200, { status: "ok" });

  const user = identity(req);

  if (url === "/api/me") {
    if (!user) return send(res, 401, { error: "Not authenticated." });
    return send(res, 200, { name: user.name, roles: user.roles });
  }
  if (url.startsWith("/api/")) {
    if (!user) return send(res, 401, { error: "Not authenticated." });
    if (!user.roles.length)
      return send(res, 403, { error: "No portal role assigned. Ask an admin to add you to an access group." });
    if (isRateLimited(user.oid)) {
      res.writeHead(429, { "Content-Type": "application/json", "Retry-After": "60" });
      return res.end(JSON.stringify({ error: "Too many requests — please slow down and try again shortly." }));
    }
    return proxy(req, res, user);
  }
  if (url === "/" || url === "/index.html") {
    // Hard block: an authenticated user with zero assigned roles never sees
    // the app shell — Easy Auth already stopped anonymous users; this stops
    // "signed in but not provisioned" users at the same point.
    if (user && !user.roles.length) {
      fs.readFile(path.join(PUBLIC_DIR, "no-access.html"), (err, data) => {
        if (err) return send(res, 403, { error: "No portal role assigned." });
        res.writeHead(403, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
        res.end(data.toString("utf8").replace("__USER__", user.name || "signed-in user"));
      });
      return;
    }
    return serveStatic(res, "index.html");
  }
  return serveStatic(res, url.slice(1));
}).listen(PORT, () => console.log(`ioc-portal frontend listening on :${PORT}`));
