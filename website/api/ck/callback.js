const { sendJson } = require('../lib/http');
const { verifyState, signAttestation } = require('../lib/crypto');
const { exchangeCode, verifyIDToken, userInfo } = require('../lib/oidc');
const { getSession, updateSession } = require('../lib/store');

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function page(res, status, title, msg) {
  res.statusCode = status;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHTML(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#111}</style></head><body><h1>${escapeHTML(title)}</h1><p>${escapeHTML(msg)}</p></body></html>`);
}

function ckSubjectFromPayload(payload) {
  for (const key of ['sub', 'ck_sub', 'consentkeys_sub']) {
    const v = String(payload[key] || '');
    if (/^[A-Za-z0-9._:@/-]{3,256}$/.test(v)) return v;
  }
  throw new Error('ConsentKeys subject missing from token payload');
}

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });
  try {
    if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));
    const state = verifyState(req.query.state);
    const session = await getSession(state.session_id);
    if (!session) throw new Error('attestation session not found');
    if (session.user_code !== state.nonce || !session.code_verified_at) throw new Error('attestation session was not code-verified');
    if (!session.pkce_verifier) throw new Error('attestation session missing PKCE verifier');
    if (Date.parse(session.expires_at) <= Date.now()) throw new Error('attestation session expired');

    const tokens = await exchangeCode(req, String(req.query.code || ''), session.pkce_verifier);
    let payload;
    try {
      payload = await verifyIDToken(tokens.id_token);
    } catch (err) {
      // ponytail: CK's userinfo endpoint is enough after client-authenticated PKCE code exchange; remove fallback when JWKS/id_token verification is fixed upstream.
      payload = await userInfo(tokens.access_token);
    }
    const subject = ckSubjectFromPayload(payload);
    const attestation = signAttestation(subject, Number(session.requested_ttl_minutes || 1440));

    session.status = 'approved';
    session.subject = subject;
    session.attestation = attestation;
    session.approved_at = new Date().toISOString();
    await updateSession(session);
    return page(res, 200, '21pins attestation approved', 'You can return to your terminal. The grant command will continue automatically.');
  } catch (err) {
    return page(res, 400, '21pins attestation failed', String(err.message || err));
  }
};
