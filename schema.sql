-- LANLORDS Messenger database. Safe to run more than once: paste it all into
-- Supabase → SQL Editor → New query → Run.
-- The server only ever stores public keys, password-locked private keys, ciphertext and encrypted files.

-- ---------- tables ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_.]{3,20}$'),
  display text not null check (char_length(display) between 1 and 40),
  pub text not null,                       -- public key (hex), safe to share
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.key_backups (
  user_id uuid primary key references auth.users(id) on delete cascade,
  salt text not null, iv text not null,
  ct text not null,                        -- private key, encrypted with the user's password
  iter int not null
);

create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  recipient uuid not null references public.profiles(id) on delete cascade,
  from_user text not null,
  to_user text not null,
  at bigint not null,
  salt text not null, iv text not null,
  ct text not null check (char_length(ct) < 8000),   -- ciphertext only
  created_at timestamptz not null default now()
);
alter table public.messages add column if not exists file_path text;          -- encrypted attachment in storage
alter table public.messages add column if not exists read_at timestamptz;      -- "Seen"
alter table public.messages add column if not exists expires_at timestamptz;   -- disappearing messages
create index if not exists messages_sender_idx on public.messages (sender, id desc);
create index if not exists messages_recipient_idx on public.messages (recipient, id desc);
create index if not exists messages_expires_idx on public.messages (expires_at) where expires_at is not null;

create table if not exists public.friendships (
  id bigint generated always as identity primary key,
  requester uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  addressee uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'blocked')),
  blocked_by uuid references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (requester <> addressee)
);
create unique index if not exists friendships_pair on public.friendships (least(requester, addressee), greatest(requester, addressee));

create table if not exists public.chat_settings (
  user_a uuid not null references public.profiles(id) on delete cascade,
  user_b uuid not null references public.profiles(id) on delete cascade,
  ttl int not null default 0 check (ttl between 0 and 604800),   -- seconds; 0 = messages stay
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now(),
  primary key (user_a, user_b),
  check (user_a < user_b)
);

create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  reported uuid not null references public.profiles(id) on delete cascade,
  reason text not null check (char_length(reason) between 1 and 500),
  created_at timestamptz not null default now()
);

-- ---------- functions and triggers ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.are_friends(a uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from friendships where status = 'accepted'
    and least(requester, addressee) = least(a, b) and greatest(requester, addressee) = greatest(a, b));
$$;

-- Only the invited person can accept; a block can only be undone by deleting it (by the blocker).
create or replace function public.friendship_guard() returns trigger
language plpgsql as $$
begin
  if tg_op = 'INSERT' then
    new.requester := auth.uid();
    if new.status = 'blocked' then new.blocked_by := auth.uid();
    else new.status := 'pending'; new.blocked_by := null; end if;
    return new;
  end if;
  if new.requester <> old.requester or new.addressee <> old.addressee then raise exception 'You cannot change who a request is between.'; end if;
  if old.status = 'blocked' then raise exception 'Unblock first.'; end if;
  if new.status = 'accepted' and not (old.status = 'pending' and auth.uid() = old.addressee) then raise exception 'Only the invited person can accept.'; end if;
  if new.status = 'pending' and old.status <> 'pending' then raise exception 'Not allowed.'; end if;
  if new.status = 'blocked' then new.blocked_by := auth.uid(); else new.blocked_by := null; end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists friendship_guard on public.friendships;
create trigger friendship_guard before insert or update on public.friendships
  for each row execute function public.friendship_guard();

-- Disappearing messages: the server stamps the expiry from the chat's setting.
create or replace function public.set_message_expiry() returns trigger
language plpgsql security definer set search_path = public as $$
declare t int;
begin
  select ttl into t from chat_settings
   where user_a = least(new.sender, new.recipient) and user_b = greatest(new.sender, new.recipient);
  new.expires_at := case when coalesce(t, 0) > 0 then now() + make_interval(secs => t) else null end;
  new.read_at := null;
  return new;
end $$;
drop trigger if exists messages_expiry on public.messages;
create trigger messages_expiry before insert on public.messages
  for each row execute function public.set_message_expiry();

-- "Seen": the receiver marks a chat as read (only the read time can change).
create or replace function public.mark_read(peer uuid) returns void
language sql security definer set search_path = public as $$
  update messages set read_at = now()
   where recipient = auth.uid() and sender = peer and read_at is null
     and (expires_at is null or expires_at > now());
$$;

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.key_backups enable row level security;
alter table public.messages enable row level security;
alter table public.friendships enable row level security;
alter table public.chat_settings enable row level security;
alter table public.reports enable row level security;

-- Profiles (username, display name, public key) are a public directory.
drop policy if exists "profiles are public" on public.profiles;
create policy "profiles are public" on public.profiles for select to anon, authenticated using (true);
drop policy if exists "create your own profile" on public.profiles;
create policy "create your own profile" on public.profiles for insert to authenticated
  with check (id = auth.uid() and role = 'user');

-- Only you can read your locked private key.
drop policy if exists "read your key backup" on public.key_backups;
create policy "read your key backup" on public.key_backups for select to authenticated using (user_id = auth.uid());
drop policy if exists "save your key backup" on public.key_backups;
create policy "save your key backup" on public.key_backups for insert to authenticated with check (user_id = auth.uid());

-- You see only your own conversations (the admin sees every row, but only as ciphertext).
-- Expired messages disappear at once, even before the cleanup job deletes them.
drop policy if exists "read your messages" on public.messages;
create policy "read your messages" on public.messages for select to authenticated
  using ((sender = auth.uid() or recipient = auth.uid() or public.is_admin())
         and (expires_at is null or expires_at > now()));
-- You can only message friends.
drop policy if exists "send as yourself" on public.messages;
create policy "send as yourself" on public.messages for insert to authenticated
  with check (
    sender = auth.uid()
    and from_user = (select username from public.profiles where id = auth.uid())
    and to_user = (select username from public.profiles where id = recipient)
    and public.are_friends(auth.uid(), recipient)
  );

drop policy if exists "see your friendships" on public.friendships;
create policy "see your friendships" on public.friendships for select to authenticated
  using (auth.uid() in (requester, addressee) or public.is_admin());
drop policy if exists "send a request or block" on public.friendships;
create policy "send a request or block" on public.friendships for insert to authenticated
  with check (requester = auth.uid() and addressee <> auth.uid());
drop policy if exists "answer or block" on public.friendships;
create policy "answer or block" on public.friendships for update to authenticated
  using (auth.uid() in (requester, addressee)) with check (auth.uid() in (requester, addressee));
drop policy if exists "cancel, decline, unfriend or unblock" on public.friendships;
create policy "cancel, decline, unfriend or unblock" on public.friendships for delete to authenticated
  using (auth.uid() in (requester, addressee) and (status <> 'blocked' or blocked_by = auth.uid()));

drop policy if exists "see your chat settings" on public.chat_settings;
create policy "see your chat settings" on public.chat_settings for select to authenticated
  using (auth.uid() in (user_a, user_b));
drop policy if exists "set your chat settings" on public.chat_settings;
create policy "set your chat settings" on public.chat_settings for insert to authenticated
  with check (auth.uid() in (user_a, user_b) and public.are_friends(user_a, user_b));
drop policy if exists "change your chat settings" on public.chat_settings;
create policy "change your chat settings" on public.chat_settings for update to authenticated
  using (auth.uid() in (user_a, user_b)) with check (auth.uid() in (user_a, user_b) and public.are_friends(user_a, user_b));

drop policy if exists "file a report" on public.reports;
create policy "file a report" on public.reports for insert to authenticated
  with check (reporter = auth.uid() and reported <> auth.uid());
drop policy if exists "admin reads reports" on public.reports;
create policy "admin reads reports" on public.reports for select to authenticated using (public.is_admin());

grant select on public.profiles to anon, authenticated;
grant insert on public.profiles to authenticated;
grant select, insert on public.key_backups to authenticated;
grant select, insert on public.messages to authenticated;
grant select, insert, update, delete on public.friendships to authenticated;
grant select, insert, update on public.chat_settings to authenticated;
grant select, insert on public.reports to authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.are_friends(uuid, uuid) to authenticated;
grant execute on function public.mark_read(uuid) to authenticated;

-- ---------- encrypted attachments (Supabase Storage) ----------
insert into storage.buckets (id, name, public, file_size_limit)
values ('attachments', 'attachments', false, 15728640)
on conflict (id) do nothing;

-- Upload only into your own folder; read a file only if it belongs to a message you can see.
drop policy if exists "lanlords upload own attachments" on storage.objects;
create policy "lanlords upload own attachments" on storage.objects for insert to authenticated
  with check (bucket_id = 'attachments' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "lanlords read attachments in your chats" on storage.objects;
create policy "lanlords read attachments in your chats" on storage.objects for select to authenticated
  using (bucket_id = 'attachments' and (
    (storage.foldername(name))[1] = auth.uid()::text
    or exists (select 1 from public.messages m where m.file_path = storage.objects.name)));
drop policy if exists "lanlords delete own attachments" on storage.objects;
create policy "lanlords delete own attachments" on storage.objects for delete to authenticated
  using (bucket_id = 'attachments' and (storage.foldername(name))[1] = auth.uid()::text);

-- ---------- profiles: picture, background and bio ----------
alter table public.profiles add column if not exists bio text not null default '' check (char_length(bio) <= 160);
alter table public.profiles add column if not exists avatar_path text;
alter table public.profiles add column if not exists banner_path text;
alter table public.profiles add column if not exists banner_color text not null default 'navy' check (banner_color ~ '^[a-z]{1,12}$');

-- Through the app you can change how you look, never your username, key or role.
create or replace function public.profile_guard() returns trigger
language plpgsql as $$
begin
  if current_user in ('anon', 'authenticated') then
    new.id := old.id; new.username := old.username; new.pub := old.pub;
    new.role := old.role; new.created_at := old.created_at;
  end if;
  return new;
end $$;
drop trigger if exists profile_guard on public.profiles;
create trigger profile_guard before update on public.profiles
  for each row execute function public.profile_guard();

drop policy if exists "edit your own profile" on public.profiles;
create policy "edit your own profile" on public.profiles for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid()
    and (avatar_path is null or split_part(avatar_path, '/', 1) = auth.uid()::text)
    and (banner_path is null or split_part(banner_path, '/', 1) = auth.uid()::text));
revoke update on public.profiles from anon, authenticated;
grant update (display, bio, avatar_path, banner_path, banner_color) on public.profiles to authenticated;

-- Profile pictures and backgrounds are public (like on Messenger); messages and attachments stay encrypted.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 5242880, array['image/png', 'image/jpeg', 'image/gif', 'image/webp'])
on conflict (id) do update set public = true, file_size_limit = 5242880,
  allowed_mime_types = array['image/png', 'image/jpeg', 'image/gif', 'image/webp'];
drop policy if exists "lanlords upload own profile pictures" on storage.objects;
create policy "lanlords upload own profile pictures" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "lanlords see own profile pictures" on storage.objects;
create policy "lanlords see own profile pictures" on storage.objects for select to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists "lanlords delete own profile pictures" on storage.objects;
create policy "lanlords delete own profile pictures" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- ---------- admin: delete an account ----------
-- Deletes the login, which removes the profile, locked key, messages, friendships and reports with it.
create or replace function public.admin_delete_user(target uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only the admin can delete accounts.'; end if;
  if exists (select 1 from profiles where id = target and role = 'admin') then raise exception 'Admin accounts cannot be deleted here.'; end if;
  delete from auth.users where id = target;
end $$;
revoke execute on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.admin_delete_user(uuid) to authenticated;
-- The admin may clean up a deleted user's files (still encrypted; the admin cannot open them).
drop policy if exists "lanlords admin sees files" on storage.objects;
create policy "lanlords admin sees files" on storage.objects for select to authenticated
  using (bucket_id in ('attachments', 'avatars') and public.is_admin());
drop policy if exists "lanlords admin removes files" on storage.objects;
create policy "lanlords admin removes files" on storage.objects for delete to authenticated
  using (bucket_id in ('attachments', 'avatars') and public.is_admin());

-- ---------- live updates ----------
do $$
declare t text;
begin
  foreach t in array array['messages', 'profiles', 'friendships', 'chat_settings', 'reports'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- ---------- cleanup job for disappearing messages (runs every minute) ----------
do $$ begin
  create extension if not exists pg_cron;
exception when others then raise notice 'pg_cron is not available here: %', sqlerrm;
end $$;
do $$ begin
  perform cron.schedule('lanlords-expire-messages', '* * * * *', 'delete from public.messages where expires_at < now()');
exception when others then raise notice 'Could not schedule the cleanup job (expired messages are still hidden): %', sqlerrm;
end $$;

-- To make an admin: create a normal account named "admin" in the app, then run:
-- update public.profiles set role = 'admin' where username = 'admin';
