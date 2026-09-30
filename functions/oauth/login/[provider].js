import { txCookie } from "../../_shared/cookies.js";
import { randomToken, sha256Base64url } from "../../_shared/crypto.js";
import { getProvider, getCredentials, getRedirectUri } from "../../_shared/providers.js";

const NO_STORE = { "Cache-Control": "no-store" };

export async function onRequestGet({ env, params }) {
  const name = params.provider;

  const provider = getProvider(name);
  if (!provider) {
    return new Response("Nao encontrado.", { status: 404, headers: NO_STORE });
  }

  const { clientId } = getCredentials(env, name);
  if (!env.DB || !env.PUBLIC_BASE_URL || !clientId) {
    return new Response("Configuracao incompleta.", { status: 500, headers: NO_STORE });
  }

  const txId = randomToken();
  const state = randomToken();
  const codeVerifier = randomToken();
  const nonce = provider.useNonce ? randomToken() : null; // nonce so no Google

  const codeChallenge = await sha256Base64url(codeVerifier);
  const idHash = await sha256Base64url(txId);
  const stateHash = await sha256Base64url(state);

  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 600;

  await env.DB.prepare("DELETE FROM oauth_transactions WHERE expires_at <= ?")
    .bind(now)
    .run();

  await env.DB.prepare(
    "INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
  )
    .bind(idHash, name, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  const url = new URL(provider.authUrl);
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", getRedirectUri(env, name));
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (provider.scope) url.searchParams.set("scope", provider.scope);
  if (nonce) url.searchParams.set("nonce", nonce);

  const headers = new Headers({ ...NO_STORE, Location: url.toString() });
  headers.append("Set-Cookie", txCookie(txId));
  return new Response(null, { status: 302, headers });
}
