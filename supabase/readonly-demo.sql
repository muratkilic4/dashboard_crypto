-- CryptoDash Pro: enforce owner isolation and server-side read-only demo accounts.
-- IMPORTANT: run this in the exact Supabase project configured in index_yedek.html.
-- After creating a demo Auth user manually, insert that user's UUID into
-- public.cryptodash_readonly_users (example at the bottom of this file).
-- Never expose service_role keys in the browser.

create table if not exists public.cryptodash_readonly_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.cryptodash_readonly_users enable row level security;
revoke all on table public.cryptodash_readonly_users from anon, authenticated;

create or replace function public.cryptodash_is_readonly_demo()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.cryptodash_readonly_users d
    where d.user_id = (select auth.uid())
  );
$$;
revoke all on function public.cryptodash_is_readonly_demo() from public, anon;
grant execute on function public.cryptodash_is_readonly_demo() to authenticated;

-- Transactions: replace existing policies so permissive legacy policies cannot bypass ownership.
alter table public.transactions enable row level security;
do $$
declare p record;
begin
  for p in
    select policyname from pg_policies
    where schemaname = 'public' and tablename = 'transactions'
  loop
    execute format('drop policy if exists %I on public.transactions', p.policyname);
  end loop;
end $$;

create policy "CryptoDash transactions select own"
on public.transactions for select to authenticated
using (user_id = (select auth.uid()));

create policy "CryptoDash transactions insert own non-demo"
on public.transactions for insert to authenticated
with check (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()));

create policy "CryptoDash transactions update own non-demo"
on public.transactions for update to authenticated
using (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()))
with check (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()));

create policy "CryptoDash transactions delete own non-demo"
on public.transactions for delete to authenticated
using (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()));

-- Profiles: users can read their own profile; only full accounts can update it.
-- Account/profile provisioning should be performed by trusted server-side code or the dashboard.
alter table public.profiles enable row level security;
do $$
declare p record;
begin
  for p in
    select policyname from pg_policies
    where schemaname = 'public' and tablename = 'profiles'
  loop
    execute format('drop policy if exists %I on public.profiles', p.policyname);
  end loop;
end $$;

create policy "CryptoDash profiles select own"
on public.profiles for select to authenticated
using (user_id = (select auth.uid()));

create policy "CryptoDash profiles update own non-demo"
on public.profiles for update to authenticated
using (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()))
with check (user_id = (select auth.uid()) and not (select public.cryptodash_is_readonly_demo()));

-- Keep per-user avatar read policies; add restrictive write guards so a broad
-- legacy storage policy cannot let a demo user upload, replace, or delete avatars.
alter table storage.objects enable row level security;
drop policy if exists "CryptoDash demo cannot insert avatars" on storage.objects;
create policy "CryptoDash demo cannot insert avatars"
on storage.objects as restrictive for insert to authenticated
with check (bucket_id <> 'avatars' or not (select public.cryptodash_is_readonly_demo()));

drop policy if exists "CryptoDash demo cannot update avatars" on storage.objects;
create policy "CryptoDash demo cannot update avatars"
on storage.objects as restrictive for update to authenticated
using (bucket_id <> 'avatars' or not (select public.cryptodash_is_readonly_demo()))
with check (bucket_id <> 'avatars' or not (select public.cryptodash_is_readonly_demo()));

drop policy if exists "CryptoDash demo cannot delete avatars" on storage.objects;
create policy "CryptoDash demo cannot delete avatars"
on storage.objects as restrictive for delete to authenticated
using (bucket_id <> 'avatars' or not (select public.cryptodash_is_readonly_demo()));

-- After the Auth user and matching public.profiles row are created, mark that user
-- as read-only by running this separately with their real Auth user UUID:
-- insert into public.cryptodash_readonly_users (user_id) values ('PASTE_REAL_AUTH_USER_UUID_HERE');

-- NOTE: this migration replaces all existing policies on public.transactions and
-- public.profiles with owner-only policies. Review any custom cross-user admin workflow
-- before running; the current client code queries only the signed-in user's own rows.
