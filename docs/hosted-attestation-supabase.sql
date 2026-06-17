-- 21pins hosted CK attestation sessions
-- Run in the production shared Supabase project: dream ideas (mvyfgqomrzbnphjcsupj).

create table if not exists public.pins21_hosted_attestation_sessions (
  session_id text primary key,
  user_code text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'expired')),
  requested_ttl_minutes integer not null default 1440,
  attempts integer not null default 0,
  subject text,
  attestation jsonb,
  pkce_verifier text,
  error text,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  code_verified_at timestamptz,
  approved_at timestamptz
);

alter table public.pins21_hosted_attestation_sessions
  add column if not exists pkce_verifier text;

create index if not exists pins21_hosted_attestation_sessions_expires_at_idx
  on public.pins21_hosted_attestation_sessions (expires_at);

alter table public.pins21_hosted_attestation_sessions enable row level security;

revoke all on table public.pins21_hosted_attestation_sessions from anon;
revoke all on table public.pins21_hosted_attestation_sessions from authenticated;

-- No anon/auth policies: server-side Vercel functions use the service role key, which bypasses RLS.
