// Vercel Routing Middleware (runs before the vercel.json rewrite to Render).
//
// Adds `x-opsec-proxy-secret` to every proxied request so the API can tell
// genuine Vercel traffic from clients that call the public *.onrender.com
// origin directly and forge `x-vercel-forwarded-for` (audit S1/S2,
// 2026-11-13). The value comes from the Vercel environment variable
// PLATFORM_PROXY_SECRET and must equal the one set on Render; it is never in
// the repository. When it is unset, requests pass through unchanged.
//
// Dependency-free on purpose (no package.json at the repo root, so the
// project's FastAPI build detection is untouched). It emits exactly the
// headers that `next({ request: { headers } })` from @vercel/functions emits:
// `x-middleware-override-headers` lists every request header to forward and
// `x-middleware-request-<name>` carries each value. A client-supplied
// x-opsec-proxy-secret is always replaced or dropped.

const SECRET_HEADER = "x-opsec-proxy-secret";

export default function middleware(request) {
  const secret = (process.env.PLATFORM_PROXY_SECRET || "").trim();
  const forwarded = new Headers(request.headers);
  forwarded.delete(SECRET_HEADER);
  if (secret) forwarded.set(SECRET_HEADER, secret);

  const out = new Headers({ "x-middleware-next": "1" });
  const names = [];
  forwarded.forEach((value, name) => {
    names.push(name);
    out.set(`x-middleware-request-${name}`, value);
  });
  out.set("x-middleware-override-headers", names.join(","));
  return new Response(null, { headers: out });
}
