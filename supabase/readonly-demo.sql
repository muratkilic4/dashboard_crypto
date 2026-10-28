-- CryptoDash Pro: enforce owner isolation and server-side read-only demo accounts.
-- Run this migration in the SAME Supabase project used by index_yedek.html.
-- Mark manually-created demo Auth users with app_metadata.access_mode = "readonly_demo".
-- app_metadata is server-controlled; do NOT use user_metadata for authorization.

create or replace function public.cryptodash_is_readonly_demo()
returns boolean
language sql
stable
as $$
  select coalesce(auth.jwt() -> 'app_metadata' ->> 'access_mode', '') = 'readonly_demo';
$$;

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

-- Keep the existing per-user avatar read policies, but add restrictive write guards
-- so a broad legacy storage policy cannot allow a demo user to upload/replace/delete.
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

grant execute on function public.cryptodash_is_readonly_demo() to authenticated;

-- NOTE: this migration intentionally removes existing policies on transactions/profiles
-- and replaces them with owner-only policies. Review any custom admin cross-user workflow
-- before running; this app's current client queries operate on the signed-in user's own rows.
