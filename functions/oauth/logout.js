import { getCookie, SESSION_COOKIE, clearSessionCookie } from "../_shared/cookies.js";
import { sha256Base64url } from "../_shared/crypto.js";

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin");
  if (!origin || origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem invalida.", {
      status: 403,
      headers: { "Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const cookie = getCookie(request, SESSION_COOKIE);
  if (cookie) {
    const idHash = await sha256Base64url(cookie);
    await env.DB.prepare("DELETE FROM sessions WHERE id_hash = ?").bind(idHash).run();
  }

  const headers = new Headers({
    "Cache-Control": "no-store",
    Location: env.PUBLIC_BASE_URL,
  });
  headers.append("Set-Cookie", clearSessionCookie());
  return new Response(null, { status: 303, headers });
}

export function onRequest() {
  return new Response("Metodo nao permitido.", {
    status: 405,
    headers: { Allow: "POST", "Cache-Control": "no-store" },
  });
}
