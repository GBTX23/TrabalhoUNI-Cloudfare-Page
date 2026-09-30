import {
  getCookie,
  TX_COOKIE,
  clearTxCookie,
  sessionCookie,
} from "../../_shared/cookies.js";
import { randomToken, sha256Base64url, safeEqual } from "../../_shared/crypto.js";
import { getProvider, getCredentials, getRedirectUri } from "../../_shared/providers.js";
import { verifyGoogleIdToken } from "../../_shared/oidc.js";

const GITHUB_API_VERSION = "2026-03-10";
const USER_AGENT = "oauth-pages-lab";

// Resposta de erro generica (sem detalhes internos) e sem cache
function fail(status = 400) {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
  });
  headers.append("Set-Cookie", clearTxCookie());
  return new Response("Falha no login.", { status, headers });
}

// Troca o code pelos tokens. Nao registra corpo nem resposta.
async function exchangeCode(provider, creds, code, codeVerifier, redirectUri) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    code_verifier: codeVerifier,
  });
  const response = await fetch(provider.tokenUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "User-Agent": USER_AGENT,
    },
    body,
  });
  if (!response.ok) throw new Error("troca");
  return response.json();
}

async function googleIdentity(provider, creds, tokens, nonce) {
  const payload = await verifyGoogleIdToken(tokens.id_token, {
    clientId: creds.clientId,
    nonce,
    issuer: provider.issuer,
  });
  return {
    issuer: provider.issuer,
    subject: payload.sub,
    email: payload.email ?? null,
    displayName: payload.name ?? payload.email ?? null,
  };
}

async function githubIdentity(provider, creds, tokens) {
  const accessToken = tokens.access_token;
  if (typeof accessToken !== "string" || accessToken === "") throw new Error("token");
  if (String(tokens.token_type || "").toLowerCase() !== "bearer") throw new Error("tipo");

  // Consulta o perfil autenticado
  const userResponse = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": USER_AGENT,
    },
  });
  if (userResponse.status !== 200) throw new Error("perfil");
  const user = await userResponse.json();
  if (!Number.isInteger(user.id)) throw new Error("id");

  // Revoga a autorizacao concedida a OAuth App (exige 204)
  const revoke = await fetch(
    `https://api.github.com/applications/${creds.clientId}/grant`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${btoa(`${creds.clientId}:${creds.clientSecret}`)}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify({ access_token: accessToken }),
    }
  );
  if (revoke.status !== 204) throw new Error("revogacao");

  return {
    issuer: provider.issuer,
    subject: String(user.id),
    email: user.email ?? null, // pode ser nulo
    displayName: user.name || user.login || null,
  };
}

export async function onRequestGet({ request, env, params }) {
  try {
    const name = params.provider;
    const provider = getProvider(name);
    if (!provider) {
      return new Response("Nao encontrado.", {
        status: 404,
        headers: { "Cache-Control": "no-store" },
      });
    }

    const url = new URL(request.url);

    // 1. recusar error ou ausencia de code/state
    if (url.searchParams.get("error")) return fail();
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return fail();

    // 2. exigir o cookie temporario
    const txValue = getCookie(request, TX_COOKIE);
    if (!txValue) return fail();

    // 3. localizar a transacao pelo resumo do cookie
    const idHash = await sha256Base64url(txValue);
    const now = Math.floor(Date.now() / 1000);
    const tx = await env.DB.prepare(
      "SELECT provider, state_hash, nonce, code_verifier, expires_at FROM oauth_transactions WHERE id_hash = ?"
    )
      .bind(idHash)
      .first();
    if (!tx) return fail();

    // 5. apagar a transacao antes de concluir (uso unico, mesmo se algo falhar)
    const deleted = await env.DB.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?")
      .bind(idHash)
      .run();
    if (!deleted.meta || deleted.meta.changes !== 1) return fail();

    if (tx.expires_at <= now) return fail();
    if (tx.provider !== name) return fail();

    // 4. comparar o resumo do state
    const stateHash = await sha256Base64url(state);
    if (!safeEqual(stateHash, tx.state_hash)) return fail();

    // 6. trocar o codigo pelos tokens do provedor correto
    const creds = getCredentials(env, name);
    const tokens = await exchangeCode(
      provider,
      creds,
      code,
      tx.code_verifier,
      getRedirectUri(env, name)
    );

    // 7. validar a identidade conforme o provedor
    const identity =
      name === "google"
        ? await googleIdentity(provider, creds, tokens, tx.nonce)
        : await githubIdentity(provider, creds, tokens);

    // 8. criar a sessao opaca (so o resumo vai para o D1)
    const sessionId = randomToken();
    const sessionHash = await sha256Base64url(sessionId);
    await env.DB.prepare(
      "INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(
        sessionHash,
        identity.issuer,
        identity.subject,
        identity.email,
        identity.displayName,
        now + 28800,
        now
      )
      .run();

    // 9 e 10. limpar cookie temporario e voltar para a pagina
    const headers = new Headers({
      "Cache-Control": "no-store",
      Location: env.PUBLIC_BASE_URL,
    });
    headers.append("Set-Cookie", sessionCookie(sessionId));
    headers.append("Set-Cookie", clearTxCookie());
    return new Response(null, { status: 302, headers });
  } catch (err) {
    // Nao registra tokens, codigos nem corpos de resposta
    return fail();
  }
}
