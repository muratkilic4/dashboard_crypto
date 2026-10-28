-- CryptoDash Pro: add editable profile details without changing usernames.
alter table public.profiles
  add column if not exists first_name text not null default '',
  add column if not exists last_name text not null default '',
  add column if not exists avatar_url text not null default '';

-- Public bucket is used only for profile avatar images; uploads are restricted to the owner's folder.
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true)
on conflict (id) do update set public = true;

drop policy if exists "CryptoDash users can view own avatar objects" on storage.objects;
create policy "CryptoDash users can view own avatar objects"
on storage.objects for select to authenticated
using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "CryptoDash users can upload own avatar objects" on storage.objects;
create policy "CryptoDash users can upload own avatar objects"
on storage.objects for insert to authenticated
with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "CryptoDash users can update own avatar objects" on storage.objects;
create policy "CryptoDash users can update own avatar objects"
on storage.objects for update to authenticated
using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text)
with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
