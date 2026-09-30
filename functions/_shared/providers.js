const PROVIDERS = {
  google: {
    issuer: "https://accounts.google.com",
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
    useNonce: true,
  },
  github: {
    issuer: "https://github.com",
    authUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    scope: null, // GitHub: sem scope
    useNonce: false, // GitHub: sem nonce
  },
};

export function getProvider(name) {
  return Object.prototype.hasOwnProperty.call(PROVIDERS, name)
    ? PROVIDERS[name]
    : null;
}

export function getCredentials(env, name) {
  if (name === "google") {
    return { clientId: env.GOOGLE_CLIENT_ID, clientSecret: env.GOOGLE_CLIENT_SECRET };
  }
  return { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
}

export function getRedirectUri(env, name) {
  return `${env.PUBLIC_BASE_URL}/oauth/callback/${name}`;
}
