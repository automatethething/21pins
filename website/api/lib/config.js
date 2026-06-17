function env(name) {
  return process.env[name] || '';
}

function issuer() {
  return env('PINS21_HOSTED_ISSUER') || env('PINS21_HOSTED_URL') || 'https://21pins.com';
}

function publicBaseUrl(req) {
  const configured = env('PINS21_HOSTED_URL');
  if (configured) return configured.replace(/\/$/, '');
  const host = req.headers['x-forwarded-host'] || req.headers.host || '21pins.com';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  return `${proto}://${host}`.replace(/\/$/, '');
}

function required(name) {
  const value = env(name);
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

function hasSupabase() {
  return Boolean(env('SUPABASE_URL') && env('SUPABASE_SERVICE_ROLE_KEY'));
}

function hasOIDC() {
  return Boolean(env('CONSENTKEYS_CLIENT_ID') && env('CONSENTKEYS_CLIENT_SECRET'));
}

function hasSigningKey() {
  return Boolean(env('PINS21_HOSTED_ED25519_PRIVATE_KEY_PEM'));
}

function hasStateSecret() {
  return Boolean(env('PINS21_HOSTED_STATE_SECRET'));
}

module.exports = { env, issuer, publicBaseUrl, required, hasSupabase, hasOIDC, hasSigningKey, hasStateSecret };
