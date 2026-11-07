create extension if not exists "pgcrypto";

create table if not exists public.users (
  user_id uuid primary key default gen_random_uuid(),
  name text not null,
  email text not null unique,
  password text,
  phone_number text,
  role text not null default 'user' check (role in ('user', 'admin')),
  email_verified boolean not null default false,
  account_status text not null default 'pending'
    check (account_status in ('active', 'suspended', 'banned', 'pending')),
  email_otp text,
  email_otp_expires_at timestamptz,
  reset_otp text,
  reset_otp_expires_at timestamptz,
  token_version integer not null default 0,
  profile_picture text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists users_email_idx on public.users (email);
