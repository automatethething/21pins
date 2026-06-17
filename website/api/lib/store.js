const { env } = require('./config');

const TABLE = 'pins21_hosted_attestation_sessions';
const mem = new Map();

function supabaseConfigured() {
  return Boolean(env('SUPABASE_URL') && env('SUPABASE_SERVICE_ROLE_KEY'));
}

function rowFromSession(session) {
  return {
    session_id: session.session_id,
    user_code: session.user_code,
    status: session.status || 'pending',
    requested_ttl_minutes: Number(session.requested_ttl_minutes || 1440),
    attempts: Number(session.attempts || 0),
    subject: session.subject || null,
    attestation: session.attestation || null,
    pkce_verifier: session.pkce_verifier || null,
    error: session.error || null,
    expires_at: session.expires_at,
    code_verified_at: session.code_verified_at || null,
    approved_at: session.approved_at || null,
  };
}

function sessionFromRow(row) {
  if (!row) return null;
  return {
    session_id: row.session_id,
    user_code: row.user_code,
    status: row.status,
    requested_ttl_minutes: row.requested_ttl_minutes,
    attempts: row.attempts || 0,
    subject: row.subject || undefined,
    attestation: row.attestation || undefined,
    pkce_verifier: row.pkce_verifier || undefined,
    error: row.error || undefined,
    created_at: row.created_at,
    expires_at: row.expires_at,
    code_verified_at: row.code_verified_at || undefined,
    approved_at: row.approved_at || undefined,
  };
}

async function supabaseFetch(path, options = {}) {
  const base = env('SUPABASE_URL').replace(/\/$/, '');
  const key = env('SUPABASE_SERVICE_ROLE_KEY');
  if (!base || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
  const resp = await fetch(`${base}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: key,
      authorization: `Bearer ${key}`,
      ...(options.headers || {}),
    },
  });
  const text = await resp.text();
  const body = text ? JSON.parse(text) : null;
  if (!resp.ok) throw new Error(body?.message || body?.error || `Supabase request failed: ${resp.status}`);
  return body;
}

async function saveSession(session) {
  if (supabaseConfigured()) {
    await supabaseFetch(`${TABLE}?on_conflict=session_id`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        prefer: 'resolution=merge-duplicates,return=minimal',
      },
      body: JSON.stringify(rowFromSession(session)),
    });
    return;
  }
  mem.set(session.session_id, JSON.stringify(session));
}

async function getSession(sessionID) {
  if (supabaseConfigured()) {
    const rows = await supabaseFetch(`${TABLE}?session_id=eq.${encodeURIComponent(sessionID)}&select=*&limit=1`);
    return sessionFromRow(rows && rows[0]);
  }
  const raw = mem.get(sessionID);
  return raw ? JSON.parse(raw) : null;
}

async function updateSession(session) {
  if (supabaseConfigured()) {
    await supabaseFetch(`${TABLE}?session_id=eq.${encodeURIComponent(session.session_id)}`, {
      method: 'PATCH',
      headers: {
        'content-type': 'application/json',
        prefer: 'return=minimal',
      },
      body: JSON.stringify(rowFromSession(session)),
    });
    return session;
  }
  mem.set(session.session_id, JSON.stringify(session));
  return session;
}

module.exports = { saveSession, getSession, updateSession, TABLE };
