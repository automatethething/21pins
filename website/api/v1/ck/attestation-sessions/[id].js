const { sendJson } = require('../../../lib/http');
const { getSession, updateSession } = require('../../../lib/store');

module.exports = async function handler(req, res) {
  if (req.method !== 'GET') return sendJson(res, 405, { error: 'method not allowed' });
  const id = req.query.id;
  const session = await getSession(id);
  if (!session) return sendJson(res, 404, { status: 'expired', error: 'session not found' });
  if (Date.parse(session.expires_at) <= Date.now() && session.status === 'pending') {
    session.status = 'expired';
    session.error = 'session expired';
    await updateSession(session);
  }
  if (session.status === 'approved') {
    if (String(req.query.user_code || '') !== session.user_code) return sendJson(res, 200, { status: 'pending' });
    return sendJson(res, 200, { status: 'approved', attestation: session.attestation });
  }
  if (session.status === 'denied') return sendJson(res, 200, { status: 'denied', error: session.error || 'denied' });
  if (session.status === 'expired') return sendJson(res, 200, { status: 'expired', error: session.error || 'expired' });
  sendJson(res, 200, { status: 'pending' });
};
