const { sendJson, readJson } = require('../../../lib/http');
const { publicBaseUrl, hasSupabase, hasOIDC, hasSigningKey, hasStateSecret, issuer } = require('../../../lib/config');
const { randomID, randomUserCode } = require('../../../lib/crypto');
const { saveSession } = require('../../../lib/store');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return sendJson(res, 405, { error: 'method not allowed' });
  if (!hasSupabase() || !hasOIDC() || !hasSigningKey() || !hasStateSecret()) {
    return sendJson(res, 503, { error: 'hosted CK attestation is not configured' });
  }
  let body;
  try { body = await readJson(req); } catch { return sendJson(res, 400, { error: 'invalid json' }); }
  if (body.audience !== '21pins' || body.purpose !== 'grant_create') {
    return sendJson(res, 400, { error: 'invalid attestation session request' });
  }
  const ttl = Math.max(1, Math.min(Number(body.requested_ttl_minutes || 1440), 7 * 24 * 60));
  const now = Date.now();
  const session = {
    session_id: randomID('cas'),
    user_code: randomUserCode(),
    status: 'pending',
    requested_ttl_minutes: ttl,
    attempts: 0,
    created_at: new Date(now).toISOString(),
    expires_at: new Date(now + 10 * 60_000).toISOString(),
  };
  await saveSession(session);
  const base = publicBaseUrl(req);
  sendJson(res, 200, {
    session_id: session.session_id,
    verification_url: `${base}/ck/attest?session=${encodeURIComponent(session.session_id)}`,
    user_code: session.user_code,
    expires_at: session.expires_at,
    poll_interval_seconds: 2,
    issuer: issuer(),
  });
};
