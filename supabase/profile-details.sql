-- CryptoDash Pro: add editable profile details without changing usernames.
alter table public.profiles
  add column if not exists first_name text not null default '',
  add column if not exists last_name text not null default '',
  add column if not exists avatar_url text not null default '';
