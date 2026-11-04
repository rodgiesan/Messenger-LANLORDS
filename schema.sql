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
-- Four kinds of account: patient, doctor (a medical professional), staff (front desk) and admin. Old "user" accounts become patients.
alter table public.profiles drop constraint if exists profiles_role_check;
update public.profiles set role = 'patient' where role = 'user';
alter table public.profiles add constraint profiles_role_check check (role in ('patient', 'doctor', 'staff', 'admin'));
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
alter table public.consultations add column if not exists assigned_by uuid references public.profiles(id) on delete set null;   -- staff who assigned the professional
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

-- Front-desk staff: they see the waiting room and assign professionals to patients, but never read a consultation.
create or replace function public.is_staff() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'staff');
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
    or (public.is_doctor() and exists (select 1 from consultations c where c.patient = target and c.status = 'waiting'))
    or (public.is_staff() and exists (select 1 from consultations c where c.patient = target and c.status in ('waiting', 'active')));
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
    new.patient := auth.uid(); new.doctor := null; new.status := 'waiting'; new.ttl := 0; new.assigned_by := null;
    new.created_at := now(); new.accepted_at := null; new.closed_at := null; new.closed_by := null; new.updated_at := now();
    return new;
  end if;
  if new.id <> old.id or new.patient <> old.patient or new.topic <> old.topic or new.urgency <> old.urgency or new.created_at <> old.created_at then
    raise exception 'You cannot change who or what a consultation is for.';
  end if;
  if old.status in ('closed', 'cancelled') then raise exception 'This consultation has ended.'; end if;
  new.assigned_by := old.assigned_by;
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
  using (patient = auth.uid() or doctor = auth.uid() or (status = 'waiting' and public.is_doctor()) or public.is_admin()
         or (status in ('waiting', 'active') and public.is_staff()));
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
grant execute on function public.is_staff() to authenticated;
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

-- ---------- staff: assign a professional to a waiting patient ----------
create or replace function public.staff_assign(cid bigint, doc uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_staff() then raise exception 'Only clinic staff can assign professionals.'; end if;
  if not exists (select 1 from profiles where id = doc and role = 'doctor' and verified) then
    raise exception 'Pick a verified medical professional.';
  end if;
  update consultations set status = 'active', doctor = doc, accepted_at = now(), assigned_by = auth.uid(), updated_at = now()
   where id = cid and status = 'waiting' and doctor is null and patient <> doc;
  if not found then raise exception 'This patient is no longer waiting. Someone may have accepted them already.'; end if;
end $$;
revoke execute on function public.staff_assign(bigint, uuid) from public, anon;
grant execute on function public.staff_assign(bigint, uuid) to authenticated;

-- The admin turns a patient account into a staff account, or back.
create or replace function public.admin_set_role(target uuid, new_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'Only the admin can change account types.'; end if;
  if new_role not in ('patient', 'staff') then raise exception 'Accounts can only be made patient or staff here.'; end if;
  if exists (select 1 from consultations where patient = target and status in ('waiting', 'active')) then
    raise exception 'This person has an open consultation. End it first.';
  end if;
  update profiles set role = new_role where id = target and role in ('patient', 'staff');
  if not found then raise exception 'Only patient and staff accounts can be changed.'; end if;
end $$;
revoke execute on function public.admin_set_role(uuid, text) from public, anon;
grant execute on function public.admin_set_role(uuid, text) to authenticated;

-- ---------- recovery key ----------
-- A second copy of the private key, locked with a random recovery key that only the user has.
-- With it, a forgotten password can be reset without losing old consultations.
alter table public.key_backups add column if not exists rec_salt text;
alter table public.key_backups add column if not exists rec_iv text;
alter table public.key_backups add column if not exists rec_ct text;
alter table public.key_backups add column if not exists rec_iter int;
drop policy if exists "update your key backup" on public.key_backups;
create policy "update your key backup" on public.key_backups for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
grant update on public.key_backups to authenticated;

-- Lost password and no recovery key: start over with a new key pair. Old messages can no longer be read.
create or replace function public.reset_my_keys(new_pub text, salt text, iv text, ct text, iter int,
  rsalt text, riv text, rct text, riter int) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Log in first.'; end if;
  if new_pub !~ '^04[0-9a-f]{128}$' then raise exception 'That is not a public key.'; end if;
  update profiles set pub = new_pub where id = auth.uid();
  update key_backups set salt = reset_my_keys.salt, iv = reset_my_keys.iv, ct = reset_my_keys.ct, iter = reset_my_keys.iter,
    rec_salt = rsalt, rec_iv = riv, rec_ct = rct, rec_iter = riter
   where user_id = auth.uid();
end $$;
revoke execute on function public.reset_my_keys(text, text, text, text, int, text, text, text, int) from public, anon;
grant execute on function public.reset_my_keys(text, text, text, text, int, text, text, text, int) to authenticated;

-- ---------- login alerts ----------
create table if not exists public.login_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null check (kind in ('failed_password', 'failed_2fa', 'locked', 'new_device', 'password_changed', 'keys_reset', '2fa_on', '2fa_off')),
  ip text, device text, dev_id text,
  seen boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists login_events_user_idx on public.login_events (user_id, id desc);
create table if not exists public.login_devices (
  user_id uuid not null references auth.users(id) on delete cascade,
  dev_id text not null check (dev_id ~ '^[0-9a-f]{16,64}$'),
  label text,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  primary key (user_id, dev_id)
);
alter table public.login_events enable row level security;
alter table public.login_devices enable row level security;
drop policy if exists "see your login events" on public.login_events;
create policy "see your login events" on public.login_events for select to authenticated using (user_id = auth.uid());
drop policy if exists "dismiss your login events" on public.login_events;
create policy "dismiss your login events" on public.login_events for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
revoke all on public.login_events from anon, authenticated;
grant select on public.login_events to authenticated;
grant update (seen) on public.login_events to authenticated;
revoke all on public.login_devices from anon, authenticated;

-- Where a request came from, as Supabase passes it on (first address in X-Forwarded-For) and which browser.
create or replace function public.req_ip() returns text
language sql stable as $$
  select nullif(split_part(coalesce(current_setting('request.headers', true)::json->>'x-forwarded-for', ''), ',', 1), '');
$$;
create or replace function public.req_agent() returns text
language sql stable as $$
  select left(coalesce(current_setting('request.headers', true)::json->>'user-agent', ''), 250);
$$;

create extension if not exists pgcrypto with schema extensions;

-- Log in by username. Checks the login code against Supabase's own password hash, and only then
-- gives back the account's email so the app can sign in. A wrong code is written down as an alert for
-- the owner, and after 5 wrong tries in 15 minutes the account is locked for 15 minutes.
create or replace function public.login_email(u text, code text) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare uid uuid; em text; pw text; fails int;
begin
  select p.id, au.email, au.encrypted_password into uid, em, pw
    from public.profiles p join auth.users au on au.id = p.id where p.username = lower(u);
  if uid is null then perform pg_sleep(0.2); return null; end if;
  select count(*) into fails from login_events
   where user_id = uid and kind = 'failed_password' and created_at > now() - interval '15 minutes';
  if fails >= 5 then
    if not exists (select 1 from login_events where user_id = uid and kind = 'locked' and created_at > now() - interval '15 minutes') then
      insert into login_events (user_id, kind, ip, device) values (uid, 'locked', public.req_ip(), public.req_agent());
    end if;
    return 'locked';
  end if;
  if pw is not null and pw <> '' and pw = extensions.crypt(code, pw) then
    -- Typos you made yourself just before logging in (same address and browser) are not shown as alerts.
    update login_events set seen = true
     where user_id = uid and kind = 'failed_password' and not seen and created_at > now() - interval '30 minutes'
       and ip is not distinct from public.req_ip() and device is not distinct from public.req_agent();
    return em;
  end if;
  insert into login_events (user_id, kind, ip, device) values (uid, 'failed_password', public.req_ip(), public.req_agent());
  return null;
end $$;
revoke execute on function public.login_email(text, text) from public;
grant execute on function public.login_email(text, text) to anon, authenticated;

-- The app reports what happened after a login: which device (a random id kept in the browser),
-- a wrong 2FA code, or a security change. A device seen for the first time is an alert,
-- unless it is the account's very first device.
create or replace function public.note_login(what text, dev text, label text) returns void
language plpgsql security definer set search_path = public as $$
declare fresh boolean; others boolean;
begin
  if auth.uid() is null then return; end if;
  if what not in ('login', 'failed_2fa', 'password_changed', 'keys_reset', '2fa_on', '2fa_off') then raise exception 'Unknown event.'; end if;
  if dev !~ '^[0-9a-f]{16,64}$' then dev := null; end if;
  label := left(coalesce(label, ''), 80);
  if what = 'login' then
    if dev is null then return; end if;
    select exists (select 1 from login_devices where user_id = auth.uid()) into others;
    insert into login_devices (user_id, dev_id, label) values (auth.uid(), dev, label)
      on conflict (user_id, dev_id) do update set last_seen = now(), label = excluded.label
      returning (xmax = 0) into fresh;
    if fresh and others then
      insert into login_events (user_id, kind, ip, device, dev_id) values (auth.uid(), 'new_device', public.req_ip(), label, dev);
    end if;
    return;
  end if;
  insert into login_events (user_id, kind, ip, device, dev_id) values (auth.uid(), what, public.req_ip(), label, dev);
end $$;
revoke execute on function public.note_login(text, text, text) from public, anon;
grant execute on function public.note_login(text, text, text) to authenticated;

-- ---------- two-factor authentication ----------
-- Once you turn on 2FA, a session that has only passed the password step (aal1) cannot read anything:
-- no profile, no locked key, no consultation, no message. These rules are added on top of the ones above.
create or replace function public.mfa_ok() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.jwt()->>'aal', 'aal1') = 'aal2'
    or not exists (select 1 from auth.mfa_factors f where f.user_id = auth.uid() and f.status = 'verified');
$$;
grant execute on function public.mfa_ok() to authenticated;
do $$
declare t text;
begin
  foreach t in array array['profiles', 'key_backups', 'consultations', 'messages', 'health_cards', 'reports', 'login_events'] loop
    execute format('drop policy if exists "needs 2fa when turned on" on public.%I', t);
    execute format('create policy "needs 2fa when turned on" on public.%I as restrictive for all to authenticated using (public.mfa_ok()) with check (public.mfa_ok())', t);
  end loop;
end $$;
drop policy if exists "medtalk attachments need 2fa when turned on" on storage.objects;
create policy "medtalk attachments need 2fa when turned on" on storage.objects as restrictive for all to authenticated
  using (bucket_id <> 'attachments' or public.mfa_ok()) with check (bucket_id <> 'attachments' or public.mfa_ok());

-- ---------- live updates ----------
do $$
declare t text;
begin
  foreach t in array array['messages', 'profiles', 'consultations', 'reports', 'login_events'] loop
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
