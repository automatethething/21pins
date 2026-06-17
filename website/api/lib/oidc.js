const { env, publicBaseUrl, required } = require('./config');

let discoveryCache;
let jwksCache;

async function discovery() {
  if (discoveryCache) return discoveryCache;
  const base = env('CONSENTKEYS_ISSUER') || 'https://api.consentkeys.com';
  const resp = await fetch(`${base.replace(/\/$/, '')}/.well-known/openid-configuration`);
  if (!resp.ok) throw new Error(`OIDC discovery failed: ${resp.status}`);
  discoveryCache = await resp.json();
  return discoveryCache;
}

function redirectURI(req) {
  return `${publicBaseUrl(req)}/ck/callback`;
}

async function authorizationURL(req, state, codeChallenge) {
  const d = await discovery();
  const u = new URL(d.authorization_endpoint);
  u.searchParams.set('client_id', required('CONSENTKEYS_CLIENT_ID'));
  u.searchParams.set('redirect_uri', redirectURI(req));
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', env('CONSENTKEYS_SCOPE') || 'openid profile email');
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', codeChallenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

async function exchangeCode(req, code, codeVerifier) {
  const d = await discovery();
  const params = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: redirectURI(req),
    client_id: required('CONSENTKEYS_CLIENT_ID'),
    client_secret: required('CONSENTKEYS_CLIENT_SECRET'),
    code_verifier: codeVerifier,
  });
  const resp = await fetch(d.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params,
  });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error_description || body.error || `token exchange failed: ${resp.status}`);
  return body;
}

function b64json(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

async function jwks() {
  if (jwksCache) return jwksCache;
  const d = await discovery();
  const resp = await fetch(d.jwks_uri);
  if (!resp.ok) throw new Error(`JWKS fetch failed: ${resp.status}`);
  jwksCache = await resp.json();
  return jwksCache;
}

async function userInfo(accessToken) {
  const d = await discovery();
  if (!d.userinfo_endpoint) throw new Error('OIDC userinfo endpoint missing');
  const resp = await fetch(d.userinfo_endpoint, { headers: { authorization: `Bearer ${accessToken}` } });
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error_description || body.error || `userinfo failed: ${resp.status}`);
  if (!body.sub) throw new Error('userinfo missing subject');
  return body;
}

async function verifyIDToken(idToken) {
  const [h, p, s] = String(idToken || '').split('.');
  if (!h || !p || !s) throw new Error('missing id_token');
  const header = b64json(h);
  const payload = b64json(p);
  const keys = await jwks();
  const jwk = (keys.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw new Error('OIDC signing key not found');
  const crypto = require('crypto');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const alg = header.alg;
  const verifierAlg = alg === 'RS256' ? 'RSA-SHA256' : alg === 'ES256' ? 'SHA256' : null;
  if (!verifierAlg) throw new Error(`unsupported id_token alg: ${alg}`);
  const verifyKey = alg === 'ES256' ? { key, dsaEncoding: 'ieee-p1363' } : key;
  const ok = crypto.verify(verifierAlg, Buffer.from(`${h}.${p}`), verifyKey, Buffer.from(s, 'base64url'));
  if (!ok) throw new Error('invalid id_token signature');
  const d = await discovery();
  const now = Math.floor(Date.now() / 1000);
  if (payload.iss !== d.issuer) throw new Error('invalid id_token issuer');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(required('CONSENTKEYS_CLIENT_ID'))) throw new Error('invalid id_token audience');
  if (payload.exp && payload.exp <= now) throw new Error('expired id_token');
  if (!payload.sub) throw new Error('id_token missing subject');
  return payload;
}

module.exports = { authorizationURL, exchangeCode, verifyIDToken, userInfo };
