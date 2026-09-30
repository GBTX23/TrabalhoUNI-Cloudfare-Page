const encoder = new TextEncoder();

export function bytesToBase64url(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlToBytes(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64urlToString(text) {
  return new TextDecoder().decode(base64urlToBytes(text));
}

// 32 bytes aleatorios em Base64URL sem preenchimento (43 caracteres)
export function randomToken() {
  return bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)));
}

// SHA-256 em Base64URL (usado em code_challenge e nos resumos guardados no D1)
export async function sha256Base64url(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return bytesToBase64url(new Uint8Array(digest));
}

// Comparacao em tempo constante
export function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
