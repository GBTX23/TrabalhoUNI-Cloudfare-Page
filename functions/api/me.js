import { getCookie, SESSION_COOKIE } from "../_shared/cookies.js";
import { sha256Base64url } from "../_shared/crypto.js";

const NO_STORE = { "Cache-Control": "no-store" };

function unauthorized() {
  return Response.json({ error: "unauthenticated" }, { status: 401, headers: NO_STORE });
}

export async function onRequestGet({ request, env }) {
  const cookie = getCookie(request, SESSION_COOKIE);
  if (!cookie) return unauthorized();

  const idHash = await sha256Base64url(cookie);
  const now = Math.floor(Date.now() / 1000);

  const session = await env.DB.prepare(
    "SELECT email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?"
  )
    .bind(idHash, now)
    .first();

  if (!session) return unauthorized();

  return Response.json(
    { email: session.email ?? null, displayName: session.display_name ?? null },
    { headers: NO_STORE }
  );
}
