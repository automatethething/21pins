const { sendJson } = require('./lib/http');
const { hasSupabase, hasOIDC, hasSigningKey, hasStateSecret, issuer } = require('./lib/config');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });
  const checks = {
    supabase: hasSupabase(),
    consentkeys_oidc: hasOIDC(),
    signing_key: hasSigningKey(),
    state_secret: hasStateSecret(),
  };
  const ok = checks.supabase && checks.consentkeys_oidc && checks.signing_key && checks.state_secret;
  sendJson(res, ok ? 200 : 503, {
    ok,
    service: '21pins hosted control plane',
    issuer: issuer(),
    ck_attestation_available: ok,
    checks,
  });
};
