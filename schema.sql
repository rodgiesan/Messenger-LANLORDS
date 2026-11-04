-- MedTalk database (medical consultations). Safe to run more than once: paste it all into
-- Supabase → SQL Editor → New query → Run. It upgrades the old LANLORDS Messenger tables in place.
-- The server only ever stores public keys, password-locked private keys, ciphertext and encrypted files.

-- ---------- accounts ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null check (username ~ '^[a-z0-9_.]{3,20}$'),
  display text not null check (char_length(display) between 1 and 40),
  pub text not null,                       -- public key (hex), safe to share
  role text not null default 'patient',
  created_at timestamptz not null default now()
);
-- Three kinds of account: patient, doctor (a medical professional) and admin. Old "user" accounts become patients.
alter table public.profiles drop constraint if exists profiles_role_check;
update public.profiles set role = 'patient' where role = 'user';
alter table public.profiles add constraint profiles_role_check check (role in ('patient', 'doctor', 'admin'));
alter table public.profiles alter column role set default 'patient';
alter table public.profiles add column if not exists verified boolean not null default false;   -- professionals are checked by the admin
alter table public.profiles add column if not exists specialty text not null default '' check (char_length(specialty) <= 60);
alter table public.profiles add column if not exists license text not null default '' check (char_length(license) <= 40);
alter table public.profiles add column if not exists bio text not null default '' check (char_length(bio) <= 160);
alter table public.profiles add column if not exists avatar_path text;
alter table public.profiles add column if not exists banner_path text;
alter table public.profiles add column if not exists banner_color text not null default 'navy' check (banner_color ~ '^[a-z]{1,12}$');

create table if not exists public.key_backups (
  user_id uuid primary key references auth.users(id) on delete cascade,
  salt text not null, iv text not null,
  ct text not null,                        -- private key, encrypted with the user's password
  iter int not null
);

-- ---------- consultations ----------
-- A patient asks for a consultation; any verified professional can accept it, and then only those two can talk.
create table if not exists public.consultations (
  id bigint generated always as identity primary key,
  patient uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  doctor uuid references public.profiles(id) on delete cascade,
  topic text not null check (topic ~ '^[a-z_]{1,20}$'),
  urgency text not null default 'routine' check (urgency in ('routine', 'soon', 'urgent')),
  status text not null default 'waiting' check (status in ('waiting', 'active', 'closed', 'cancelled')),
  ttl int not null default 0 check (ttl between 0 and 604800),   -- disappearing messages, in seconds; 0 = messages stay
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  closed_at timestamptz,
  closed_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now(),
  check (doctor is null or doctor <> patient)
);
create index if not exists consultations_patient_idx on public.consultations (patient);
create index if not exists consultations_doctor_idx on public.consultations (doctor);
create index if not exists consultations_waiting_idx on public.consultations (created_at) where status = 'waiting';

-- ---------- messages ----------
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
alter table public.messages add column if not exists consultation_id bigint references public.consultations(id) on delete cascade;
create index if not exists messages_sender_idx on public.messages (sender, id desc);
create index if not exists messages_recipient_idx on public.messages (recipient, id desc);
create index if not exists messages_consultation_idx on public.messages (consultation_id, id);
create index if not exists messages_expires_idx on public.messages (expires_at) where expires_at is not null;

-- ---------- encrypted health cards ----------
-- Allergies, medicines and so on, encrypted on the patient's device with a key only they have.
create table if not exists public.health_cards (
  user_id uuid primary key default auth.uid() references public.profiles(id) on delete cascade,
  salt text not null, iv text not null,
  ct text not null check (char_length(ct) < 6000),
  updated_at timestamptz not null default now()
);

create table if not exists public.reports (
  id bigint generated always as identity primary key,
  reporter uuid not null default auth.uid() references public.profiles(id) on delete cascade,
  reported uuid not null references public.profiles(id) on delete cascade,
  reason text not null check (char_length(reason) between 1 and 500),
  created_at timestamptz not null default now()
);

-- ---------- functions ----------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

-- A medical professional the admin has verified.
create or replace function public.is_doctor() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'doctor' and verified);
$$;

-- Who may see whose profile: yourself, verified professionals (a public directory), the other person
-- in one of your consultations, and, for verified professionals, patients who are waiting for one.
-- Nobody else can even find out who is a patient.
create or replace function public.can_see_profile(target uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select target = auth.uid()
    or public.is_admin()
    or exists (select 1 from profiles p where p.id = target and p.role = 'doctor' and p.verified)
    or exists (select 1 from consultations c
               where (c.patient = auth.uid() and c.doctor = target) or (c.doctor = auth.uid() and c.patient = target))
    or (public.is_doctor() and exists (select 1 from consultations c where c.patient = target and c.status = 'waiting'));
$$;

-- Sign-up checks a username without being able to list anybody.
create or replace function public.username_available(u text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from profiles where username = lower(u));
$$;

-- You can message someone only inside an open consultation you both belong to.
create or replace function public.can_message(cid bigint, other uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from consultations c where c.id = cid and c.status = 'active'
    and ((c.patient = auth.uid() and c.doctor = other) or (c.doctor = auth.uid() and c.patient = other)));
$$;

-- The rules of a consultation, checked by the database whatever the app sends:
-- only patients can ask, only verified professionals can accept, nobody can take over someone else's patient,
-- and an ended consultation cannot be reopened.
create or replace function public.consultation_guard() returns trigger
language plpgsql set search_path = public as $$
begin
  if current_user not in ('anon', 'authenticated') then return new; end if;   -- the SQL Editor may fix things by hand
  if tg_op = 'INSERT' then
    if not exists (select 1 from profiles where id = auth.uid() and role = 'patient') then
      raise exception 'Only patients can ask for a consultation.';
    end if;
    if (select count(*) from consultations where patient = auth.uid() and status in ('waiting', 'active')) >= 3 then
      raise exception 'You already have 3 open consultations. Finish or cancel one first.';
    end if;
    new.patient := auth.uid(); new.doctor := null; new.status := 'waiting'; new.ttl := 0;
    new.created_at := now(); new.accepted_at := null; new.closed_at := null; new.closed_by := null; new.updated_at := now();
    return new;
  end if;
  if new.id <> old.id or new.patient <> old.patient or new.topic <> old.topic or new.urgency <> old.urgency or new.created_at <> old.created_at then
    raise exception 'You cannot change who or what a consultation is for.';
  end if;
  if old.status in ('closed', 'cancelled') then raise exception 'This consultation has ended.'; end if;
  if old.status = 'waiting' then
    if new.status = 'active' then
      if not public.is_doctor() then raise exception 'Only a verified medical professional can accept.'; end if;
      if old.doctor is not null then raise exception 'Another professional already accepted this.'; end if;
      new.doctor := auth.uid(); new.accepted_at := now();
    elsif new.status = 'cancelled' then
      if auth.uid() <> old.patient then raise exception 'Only the patient can cancel a request.'; end if;
      new.doctor := null; new.closed_at := now(); new.closed_by := auth.uid();
    else
      raise exception 'Not allowed.';
    end if;
    new.ttl := old.ttl;
  else -- active
    if new.doctor is distinct from old.doctor then raise exception 'You cannot hand this consultation to someone else.'; end if;
    if new.status = 'closed' then new.closed_at := now(); new.closed_by := auth.uid();
    elsif new.status <> 'active' then raise exception 'Not allowed.';
    else new.closed_at := null; new.closed_by := null; end if;
    new.accepted_at := old.accepted_at;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists consultation_guard on public.consultations;
create trigger consultation_guard before insert or update on public.consultations
  for each row execute function public.consultation_guard();

-- Disappearing messages: the server stamps the expiry from the consultation's setting.
create or replace function public.set_message_expiry() returns trigger
language plpgsql security definer set search_path = public as $$
declare t int;
begin
  select ttl into t from consultations where id = new.consultation_id;
  new.expires_at := case when coalesce(t, 0) > 0 then now() + make_interval(secs => t) else null end;
  new.read_at := null;
  return new;
end $$;
drop trigger if exists messages_expiry on public.messages;
create trigger messages_expiry before insert on public.messages
  for each row execute function public.set_message_expiry();

-- "Seen": the receiver marks a consultation as read (only the read time can change).
drop function if exists public.mark_read(uuid);
create or replace function public.mark_read(cid bigint) returns void
language sql security definer set search_path = public as $$
  update messages set read_at = now()
   where recipient = auth.uid() and consultation_id = cid and read_at is null
     and (expires_at is null or expires_at > now());
$$;

-- Through the app you can change how you look and your specialty, never your username, key, role or verification.
create or replace function public.profile_guard() returns trigger
language plpgsql as $$
begin
  if current_user in ('anon', 'authenticated') then
    new.id := old.id; new.username := old.username; new.pub := old.pub;
    new.role := old.role; new.created_at := old.created_at;
    new.verified := old.verified; new.license := old.license;
    if old.role <> 'doctor' then new.specialty := old.specialty; end if;
  end if;
  return new;
end $$;
drop trigger if exists profile_guard on public.profiles;
create trigger profile_guard before update on public.profiles
  for each row execute function public.profile_guard();

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.key_backups enable row level security;
alter table public.consultations enable row level security;
alter table public.messages enable row level security;
alter table public.health_cards enable row level security;
alter table public.reports enable row level security;

-- Profiles are no longer a public directory: see can_see_profile above.
drop policy if exists "profiles are public" on public.profiles;
drop policy if exists "see profiles you are allowed to" on public.profiles;
create policy "see profiles you are allowed to" on public.profiles for select to authenticated
  using (public.can_see_profile(id));
-- New accounts are patients or (unverified) professionals; nobody can sign up as admin or pre-verified.
drop policy if exists "create your own profile" on public.profiles;
create policy "create your own profile" on public.profiles for insert to authenticated
  with check (id = auth.uid() and role in ('patient', 'doctor') and verified = false);
drop policy if exists "edit your own profile" on public.profiles;
create policy "edit your own profile" on public.profiles for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid()
    and (avatar_path is null or split_part(avatar_path, '/', 1) = auth.uid()::text)
    and (banner_path is null or split_part(banner_path, '/', 1) = auth.uid()::text));

-- Only you can read your locked private key.
drop policy if exists "read your key backup" on public.key_backups;
create policy "read your key backup" on public.key_backups for select to authenticated using (user_id = auth.uid());
drop policy if exists "save your key backup" on public.key_backups;
create policy "save your key backup" on public.key_backups for insert to authenticated with check (user_id = auth.uid());

-- Patients see only their own consultations. Professionals see the waiting room and their own patients.
drop policy if exists "see your consultations" on public.consultations;
create policy "see your consultations" on public.consultations for select to authenticated
  using (patient = auth.uid() or doctor = auth.uid() or (status = 'waiting' and public.is_doctor()) or public.is_admin());
drop policy if exists "ask for a consultation" on public.consultations;
create policy "ask for a consultation" on public.consultations for insert to authenticated
  with check (patient = auth.uid());
drop policy if exists "accept, end or change a consultation" on public.consultations;
create policy "accept, end or change a consultation" on public.consultations for update to authenticated
  using (patient = auth.uid() or doctor = auth.uid() or (status = 'waiting' and doctor is null and public.is_doctor()))
  with check (patient = auth.uid() or doctor = auth.uid());

-- You read only messages from your own consultations (the admin sees every row, but only as ciphertext).
-- Expired messages disappear at once, even before the cleanup job deletes them.
drop policy if exists "read your messages" on public.messages;
create policy "read your messages" on public.messages for select to authenticated
  using (((consultation_id is not null and (sender = auth.uid() or recipient = auth.uid())) or public.is_admin())
         and (expires_at is null or expires_at > now()));
-- You can only message the other person in an open consultation.
drop policy if exists "send as yourself" on public.messages;
create policy "send as yourself" on public.messages for insert to authenticated
  with check (
    sender = auth.uid()
    and from_user = (select username from public.profiles where id = auth.uid())
    and to_user = (select username from public.profiles where id = recipient)
    and public.can_message(consultation_id, recipient)
  );
-- "Delete for everyone": only the sender can remove their own message.
drop policy if exists "unsend your own messages" on public.messages;
create policy "unsend your own messages" on public.messages for delete to authenticated
  using (sender = auth.uid());

-- Only you can read or change your health card; the admin can count them but they are encrypted.
drop policy if exists "read your health card" on public.health_cards;
create policy "read your health card" on public.health_cards for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
drop policy if exists "save your health card" on public.health_cards;
create policy "save your health card" on public.health_cards for insert to authenticated with check (user_id = auth.uid());
drop policy if exists "update your health card" on public.health_cards;
create policy "update your health card" on public.health_cards for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
drop policy if exists "delete your health card" on public.health_cards;
create policy "delete your health card" on public.health_cards for delete to authenticated using (user_id = auth.uid());

drop policy if exists "file a report" on public.reports;
create policy "file a report" on public.reports for insert to authenticated
  with check (reporter = auth.uid() and reported <> auth.uid());
drop policy if exists "admin reads reports" on public.reports;
create policy "admin reads reports" on public.reports for select to authenticated using (public.is_admin());

revoke all on public.profiles from anon;
grant select, insert on public.profiles to authenticated;
revoke update on public.profiles from anon, authenticated;
grant update (display, bio, avatar_path, banner_path, banner_color, specialty) on public.profiles to authenticated;
grant select, insert on public.key_backups to authenticated;
grant select, insert, update on public.consultations to authenticated;
grant select, insert, delete on public.messages to authenticated;
grant select, insert, update, delete on public.health_cards to authenticated;
grant select, insert on public.reports to authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.is_doctor() to authenticated;
grant execute on function public.can_see_profile(uuid) to authenticated;
grant execute on function public.can_message(bigint, uuid) to authenticated;
grant execute on function public.mark_read(bigint) to authenticated;
grant execute on function public.username_available(text) to anon, authenticated;

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

-- Profile pictures and backgrounds are public; messages, attachments and health cards stay encrypted.
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

-- ---------- admin: verify professionals, delete accounts ----------
create or replace function public.admin_verify(target uuid, ok boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only the admin can verify professionals.'; end if;
  update profiles set verified = ok where id = target and role = 'doctor';
  if not found then raise exception 'That account is not a medical professional.'; end if;
end $$;
revoke execute on function public.admin_verify(uuid, boolean) from public, anon;
grant execute on function public.admin_verify(uuid, boolean) to authenticated;

-- Deletes the login, which removes the profile, locked key, consultations, messages, health card and reports with it.
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

-- ---------- old messenger tables ----------
-- Friend requests and per-chat settings were replaced by consultations. Lock the old tables so nothing new goes in.
do $$ begin
  if to_regclass('public.friendships') is not null then
    execute 'revoke insert, update on public.friendships from anon, authenticated';
  end if;
  if to_regclass('public.chat_settings') is not null then
    execute 'revoke insert, update on public.chat_settings from anon, authenticated';
  end if;
end $$;

-- ---------- live updates ----------
do $$
declare t text;
begin
  foreach t in array array['messages', 'profiles', 'consultations', 'reports'] loop
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
-- Professionals are verified from the admin console. To do it by hand instead:
-- update public.profiles set verified = true where username = 'their_username';
