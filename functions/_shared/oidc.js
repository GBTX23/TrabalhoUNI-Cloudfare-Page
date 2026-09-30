import { base64urlToBytes, base64urlToString } from "./crypto.js";

const DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration";
const CLOCK_SKEW = 300; // 5 minutos de tolerancia

export async function verifyGoogleIdToken(idToken, { clientId, nonce, issuer }) {
  if (typeof idToken !== "string") throw new Error("token");

  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("formato");

  const header = JSON.parse(base64urlToString(parts[0]));
  const payload = JSON.parse(base64urlToString(parts[1]));
  if (header.alg !== "RS256") throw new Error("alg");

  const discoveryResponse = await fetch(DISCOVERY_URL);
  if (!discoveryResponse.ok) throw new Error("descoberta");
  const discovery = await discoveryResponse.json();
  if (discovery.issuer !== issuer) throw new Error("emissor da descoberta");

  const jwksResponse = await fetch(discovery.jwks_uri);
  if (!jwksResponse.ok) throw new Error("jwks");
  const jwks = await jwksResponse.json();

  const jwk = (jwks.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("kid");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlToBytes(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  if (!valid) throw new Error("assinatura");

  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== issuer && payload.iss !== "accounts.google.com") {
    throw new Error("iss");
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(clientId)) throw new Error("aud");
  if (typeof payload.exp !== "number" || payload.exp <= now) throw new Error("exp");
  if (typeof payload.iat !== "number" || payload.iat > now + CLOCK_SKEW) {
    throw new Error("iat");
  }
  if (!nonce || payload.nonce !== nonce) throw new Error("nonce");
  if (typeof payload.sub !== "string" || payload.sub === "") throw new Error("sub");

  return payload;
}
