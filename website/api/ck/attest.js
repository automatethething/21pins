const { readBody } = require('../lib/http');
const { getSession, updateSession } = require('../lib/store');
const { signState, pkceVerifier, pkceChallenge } = require('../lib/crypto');
const { authorizationURL } = require('../lib/oidc');

function html(res, status, body) {
  res.statusCode = status;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>21pins ConsentKeys attestation</title><style>body{font-family:system-ui,sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem;color:#111}input,button{font:inherit;padding:.7rem;margin-top:.5rem}input{width:16rem;max-width:100%}.error{color:#9f1239}.card{border:1px solid #ddd;border-radius:14px;padding:1.5rem}</style></head><body>${body}</body></html>`);
}

module.exports = async function handler(req, res) {
  const sessionID = req.query.session;
  const session = sessionID ? await getSession(sessionID) : null;
  if (!session) return html(res, 404, '<h1>Session not found</h1><p>This attestation session may have expired.</p>');
  if (Date.parse(session.expires_at) <= Date.now()) return html(res, 410, '<h1>Session expired</h1><p>Start a new 21pins hosted attestation.</p>');

  if (req.method === 'GET') {
    return html(res, 200, `<div class="card"><h1>Verify 21pins session</h1><p>Enter the code shown in your terminal, then continue with ConsentKeys.</p><form method="post"><label>Code<br><input name="user_code" autocomplete="one-time-code" autofocus></label><br><button>Continue with ConsentKeys</button></form></div>`);
  }
  if (req.method !== 'POST') return html(res, 405, '<h1>Method not allowed</h1>');

  const raw = await readBody(req);
  const params = new URLSearchParams(raw);
  const code = String(params.get('user_code') || '').trim().toUpperCase();
  session.attempts = Number(session.attempts || 0) + 1;
  if (session.attempts > 5) {
    session.status = 'denied';
    session.error = 'too many code attempts';
    await updateSession(session);
    return html(res, 403, '<h1>Too many attempts</h1><p>Start a new attestation session.</p>');
  }
  if (code !== session.user_code) {
    await updateSession(session);
    return html(res, 400, `<div class="card"><h1>Code mismatch</h1><p class="error">That code did not match.</p><form method="post"><label>Code<br><input name="user_code" autocomplete="one-time-code" autofocus></label><br><button>Try again</button></form></div>`);
  }

  const verifier = pkceVerifier();
  session.code_verified_at = new Date().toISOString();
  session.pkce_verifier = verifier;
  await updateSession(session);
  const state = signState({ session_id: session.session_id, nonce: session.user_code, iat: Date.now() });
  const url = await authorizationURL(req, state, pkceChallenge(verifier));
  res.statusCode = 302;
  res.setHeader('location', url);
  res.end();
};
