const crypto = require('crypto');
const { env, issuer, required } = require('./config');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function randomID(prefix, bytes = 18) {
  return `${prefix}_${crypto.randomBytes(bytes).toString('base64url')}`;
}

function pkceVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function randomUserCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  const bytes = crypto.randomBytes(8);
  for (let i = 0; i < 8; i++) out += alphabet[bytes[i] % alphabet.length];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
}

function signState(payload) {
  const secret = required('PINS21_HOSTED_STATE_SECRET');
  const data = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyState(state) {
  const secret = required('PINS21_HOSTED_STATE_SECRET');
  const [data, sig] = String(state || '').split('.');
  if (!data || !sig) throw new Error('invalid state');
  const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  const got = Buffer.from(sig);
  const want = Buffer.from(expected);
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) throw new Error('invalid state signature');
  return JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
}

function goJSONTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(d.getTime())) throw new Error('invalid time');
  return d.toISOString().replace(/\.000Z$/, 'Z').replace(/(\.\d*?)0+Z$/, '$1Z');
}

function signableAttestation(att) {
  return {
    attestation_id: att.attestation_id,
    subject: att.subject,
    issuer: att.issuer,
    audience: att.audience,
    method: att.method,
    issued_at: att.issued_at,
    expires_at: att.expires_at,
    key_id: att.key_id,
  };
}

function signAttestation(subject, ttlMinutes = 1440) {
  if (!/^[A-Za-z0-9._:@/-]{3,256}$/.test(subject)) throw new Error('invalid ConsentKeys subject');
  const now = new Date();
  const issuedAt = goJSONTime(now);
  const expiresAt = goJSONTime(new Date(now.getTime() + Math.max(1, ttlMinutes) * 60_000));
  const att = {
    attestation_id: randomID('att'),
    subject,
    issuer: issuer(),
    audience: '21pins',
    method: 'hosted_ck',
    issued_at: issuedAt,
    expires_at: expiresAt,
    key_id: env('PINS21_HOSTED_KEY_ID') || 'hosted-ed25519-v1',
  };
  const pem = required('PINS21_HOSTED_ED25519_PRIVATE_KEY_PEM').replace(/\\n/g, '\n');
  const payload = Buffer.from(JSON.stringify(signableAttestation(att)));
  att.signature = crypto.sign(null, payload, crypto.createPrivateKey(pem)).toString('base64url');
  return att;
}

module.exports = { randomID, randomUserCode, pkceVerifier, pkceChallenge, signState, verifyState, signAttestation };
