-- Montresique staff applications and in-site Mail.
-- Run this in the Supabase SQL Editor before deploying the matching frontend.
-- Application uploads are private; messages are in-site account mail, not email.

create extension if not exists pgcrypto;

-- The existing application represents Discord users by provider ID. For new
-- records, authorization is anchored to auth.uid() and Discord IDs are snapshots.
create or replace function public.current_montresique_discord_id()
returns text
language sql
stable
security definer
set search_path = auth, public, pg_temp
as $$
  select i.provider_id::text
  from auth.identities as i
  where i.user_id = auth.uid()
    and i.provider = 'discord'
  order by i.updated_at desc nulls last
  limit 1;
$$;

create or replace function public.is_montresique_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
as $$
  select exists (
    select 1
    from public.team_members as tm
    where tm.discord_id = public.current_montresique_discord_id()
      and coalesce(tm.roles::text, '') not in ('', '{}', '[]', 'null')
  );
$$;

revoke all on function public.current_montresique_discord_id() from public, anon;
revoke all on function public.is_montresique_admin() from public, anon;
grant execute on function public.current_montresique_discord_id() to authenticated;
grant execute on function public.is_montresique_admin() to authenticated;

-- Account directory used only by in-site mail. The profile key is the immutable
-- Supabase Auth UUID; Discord details are only display snapshots.
create table if not exists public.montresique_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  discord_user_id text not null,
  username text not null default 'User',
  avatar_url text not null default '',
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);

alter table public.montresique_profiles enable row level security;
revoke all on public.montresique_profiles from anon, authenticated;

create or replace function public.sync_montresique_profile(p_username text, p_avatar_url text default '')
returns void
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_discord_id text;
begin
  if auth.uid() is null then
    raise exception 'Login required';
  end if;
  v_discord_id := public.current_montresique_discord_id();
  if v_discord_id is null then
    raise exception 'A Discord login is required';
  end if;

  insert into public.montresique_profiles (user_id, discord_user_id, username, avatar_url, last_seen)
  values (
    auth.uid(),
    v_discord_id,
    left(coalesce(nullif(btrim(p_username), ''), 'User'), 100),
    left(coalesce(p_avatar_url, ''), 500),
    now()
  )
  on conflict (user_id) do update set
    discord_user_id = excluded.discord_user_id,
    username = excluded.username,
    avatar_url = excluded.avatar_url,
    last_seen = now();
end;
$$;

-- Application opening/closing is publicly readable, but only admins may change it.
create table if not exists public.staff_application_settings (
  id integer primary key check (id = 1),
  is_open boolean not null default false,
  updated_at timestamptz not null default now()
);
insert into public.staff_application_settings (id, is_open)
values (1, false)
on conflict (id) do nothing;

create or replace function public.set_staff_application_settings_updated_at()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;
drop trigger if exists staff_application_settings_updated_at on public.staff_application_settings;
create trigger staff_application_settings_updated_at
before update on public.staff_application_settings
for each row execute function public.set_staff_application_settings_updated_at();

alter table public.staff_application_settings enable row level security;
revoke all on public.staff_application_settings from anon, authenticated;
grant select on public.staff_application_settings to anon, authenticated;
grant update (is_open) on public.staff_application_settings to authenticated;
drop policy if exists staff_application_settings_public_read on public.staff_application_settings;
create policy staff_application_settings_public_read
  on public.staff_application_settings for select to anon, authenticated using (true);
drop policy if exists staff_application_settings_admin_update on public.staff_application_settings;
create policy staff_application_settings_admin_update
  on public.staff_application_settings for update to authenticated
  using (public.is_montresique_admin()) with check (public.is_montresique_admin());

create table if not exists public.staff_applications (
  id uuid primary key default gen_random_uuid(),
  applicant_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  applicant_discord_id text not null default public.current_montresique_discord_id(),
  applicant_username text not null check (length(btrim(applicant_username)) between 1 and 100),
  role text not null check (length(btrim(role)) between 1 and 100),
  age_group text not null check (length(btrim(age_group)) between 1 and 40),
  willing_to_contribute boolean not null,
  divisions text[] not null check (cardinality(divisions) between 1 and 12),
  reason text not null check (length(btrim(reason)) between 1 and 2000),
  work_image_paths text[] not null check (cardinality(work_image_paths) between 1 and 5),
  trust_response text not null check (length(btrim(trust_response)) between 1 and 2000),
  discord_active boolean not null,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  reviewed_by uuid references auth.users(id) on delete set null,
  reviewed_at timestamptz,
  created_at timestamptz not null default now(),
  check ((status = 'pending' and reviewed_by is null and reviewed_at is null)
      or (status in ('accepted', 'declined') and reviewed_by is not null and reviewed_at is not null))
);
create unique index if not exists staff_applications_one_pending_per_user
  on public.staff_applications (applicant_id) where status = 'pending';
create index if not exists staff_applications_created_at_idx
  on public.staff_applications (created_at desc);

alter table public.staff_applications enable row level security;
revoke all on public.staff_applications from anon, authenticated;
grant select, insert on public.staff_applications to authenticated;
drop policy if exists staff_applications_owner_or_admin_read on public.staff_applications;
create policy staff_applications_owner_or_admin_read
  on public.staff_applications for select to authenticated
  using (applicant_id = auth.uid() or public.is_montresique_admin());
drop policy if exists staff_applications_owner_submit on public.staff_applications;
create policy staff_applications_owner_submit
  on public.staff_applications for insert to authenticated
  with check (
    applicant_id = auth.uid()
    and applicant_discord_id = public.current_montresique_discord_id()
    and status = 'pending'
    and reviewed_by is null
    and reviewed_at is null
    and exists (
      select 1 from public.staff_application_settings as settings
      where settings.id = 1 and settings.is_open
    )
    and not exists (
      select 1
      from unnest(work_image_paths) as uploaded(path)
      where uploaded.path !~ ('^' || auth.uid()::text || '/[0-9a-f-]{36}\.(jpg|png|webp|gif)$')
    )
  );

-- In-site account mailbox. Applications decisions and welcome notifications
-- are inserted atomically by the RPCs below, not by browser-supplied recipients.
create table if not exists public.montresique_mail (
  id uuid primary key default gen_random_uuid(),
  recipient_user_id uuid not null references auth.users(id) on delete cascade,
  recipient_discord_id text,
  sender_user_id uuid references auth.users(id) on delete set null,
  sender_discord_id text,
  sender_name text not null default 'Montresique',
  subject text not null check (length(btrim(subject)) between 1 and 120),
  body text not null check (length(btrim(body)) between 1 and 5000),
  kind text not null default 'direct' check (kind in ('direct', 'welcome', 'application_decision')),
  source_id uuid,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists montresique_mail_recipient_created_idx
  on public.montresique_mail (recipient_user_id, created_at desc);
create unique index if not exists montresique_mail_one_welcome_per_user
  on public.montresique_mail (recipient_user_id) where kind = 'welcome';
create unique index if not exists montresique_mail_one_application_decision
  on public.montresique_mail (source_id) where kind = 'application_decision';

alter table public.montresique_mail enable row level security;
revoke all on public.montresique_mail from anon, authenticated;
grant select on public.montresique_mail to authenticated;
drop policy if exists montresique_mail_owner_or_admin_read on public.montresique_mail;
create policy montresique_mail_owner_or_admin_read
  on public.montresique_mail for select to authenticated
  using (recipient_user_id = auth.uid() or public.is_montresique_admin());

create table if not exists public.montresique_mail_welcome_settings (
  id integer primary key check (id = 1),
  enabled boolean not null default false,
  subject text not null default 'Welcome to Montresique!',
  body text not null default 'Welcome to your Montresique account.',
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null,
  check (length(btrim(subject)) between 1 and 120),
  check (length(btrim(body)) between 1 and 5000)
);
insert into public.montresique_mail_welcome_settings (id)
values (1)
on conflict (id) do nothing;

create or replace function public.set_montresique_welcome_updated_at()
returns trigger
language plpgsql
set search_path = public, pg_temp
as $$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  return new;
end;
$$;
drop trigger if exists montresique_mail_welcome_updated_at on public.montresique_mail_welcome_settings;
create trigger montresique_mail_welcome_updated_at
before update on public.montresique_mail_welcome_settings
for each row execute function public.set_montresique_welcome_updated_at();

alter table public.montresique_mail_welcome_settings enable row level security;
revoke all on public.montresique_mail_welcome_settings from anon, authenticated;
grant select on public.montresique_mail_welcome_settings to authenticated;
grant update (enabled, subject, body) on public.montresique_mail_welcome_settings to authenticated;
drop policy if exists montresique_mail_welcome_admin_read on public.montresique_mail_welcome_settings;
create policy montresique_mail_welcome_admin_read
  on public.montresique_mail_welcome_settings for select to authenticated
  using (public.is_montresique_admin());
drop policy if exists montresique_mail_welcome_admin_update on public.montresique_mail_welcome_settings;
create policy montresique_mail_welcome_admin_update
  on public.montresique_mail_welcome_settings for update to authenticated
  using (public.is_montresique_admin()) with check (public.is_montresique_admin());

create or replace function public.get_montresique_mail_recipients()
returns table (user_id uuid, discord_user_id text, username text, last_seen timestamptz)
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if not public.is_montresique_admin() then
    raise exception 'Admin access required';
  end if;
  return query
    select p.user_id, p.discord_user_id, p.username, p.last_seen
    from public.montresique_profiles as p
    order by p.username asc, p.last_seen desc;
end;
$$;

create or replace function public.send_montresique_mail(
  p_recipient_user_id uuid,
  p_subject text,
  p_body text
)
returns uuid
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_profile public.montresique_profiles%rowtype;
  v_sender public.montresique_profiles%rowtype;
  v_id uuid;
begin
  if not public.is_montresique_admin() then
    raise exception 'Admin access required';
  end if;
  if length(btrim(coalesce(p_subject, ''))) not between 1 and 120
     or length(btrim(coalesce(p_body, ''))) not between 1 and 5000 then
    raise exception 'A subject (1-120 characters) and message (1-5000 characters) are required';
  end if;
  select * into v_profile from public.montresique_profiles where user_id = p_recipient_user_id;
  if not found then
    raise exception 'Recipient account not found';
  end if;
  select * into v_sender from public.montresique_profiles where user_id = auth.uid();

  insert into public.montresique_mail (
    recipient_user_id, recipient_discord_id, sender_user_id, sender_discord_id,
    sender_name, subject, body, kind
  ) values (
    v_profile.user_id, v_profile.discord_user_id, auth.uid(), public.current_montresique_discord_id(),
    coalesce(nullif(v_sender.username, ''), 'Montresique Developer'),
    btrim(p_subject), btrim(p_body), 'direct'
  ) returning id into v_id;
  return v_id;
end;
$$;

create or replace function public.deliver_montresique_welcome_mail()
returns boolean
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_settings public.montresique_mail_welcome_settings%rowtype;
  v_profile public.montresique_profiles%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Login required';
  end if;
  select * into v_profile from public.montresique_profiles where user_id = auth.uid();
  if not found then
    raise exception 'Account profile is not ready';
  end if;
  select * into v_settings from public.montresique_mail_welcome_settings where id = 1;
  if not coalesce(v_settings.enabled, false) then
    return false;
  end if;

  insert into public.montresique_mail (
    recipient_user_id, recipient_discord_id, sender_name, subject, body, kind
  ) values (
    auth.uid(), v_profile.discord_user_id, 'Montresique', v_settings.subject, v_settings.body, 'welcome'
  )
  on conflict (recipient_user_id) where kind = 'welcome' do nothing;
  return found;
end;
$$;

create or replace function public.mark_montresique_mail_read(p_message_id uuid)
returns void
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if auth.uid() is null then
    raise exception 'Login required';
  end if;
  update public.montresique_mail
  set read_at = coalesce(read_at, now())
  where id = p_message_id and recipient_user_id = auth.uid();
end;
$$;

create or replace function public.review_staff_application(p_application_id uuid, p_decision text)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_app public.staff_applications%rowtype;
  v_name text;
  v_new_status text;
begin
  if not public.is_montresique_admin() then
    raise exception 'Admin access required';
  end if;
  if p_decision not in ('accept', 'decline') then
    raise exception 'Decision must be accept or decline';
  end if;
  v_new_status := case when p_decision = 'accept' then 'accepted' else 'declined' end;

  select * into v_app
  from public.staff_applications
  where id = p_application_id
  for update;
  if not found then
    raise exception 'Application not found';
  end if;
  if v_app.status <> 'pending' then
    raise exception 'This application has already been reviewed';
  end if;

  update public.staff_applications
  set status = v_new_status, reviewed_by = auth.uid(), reviewed_at = now()
  where id = p_application_id;

  v_name := coalesce(nullif(v_app.applicant_username, ''), 'there');
  insert into public.montresique_mail (
    recipient_user_id, recipient_discord_id, sender_user_id, sender_discord_id,
    sender_name, subject, body, kind, source_id
  ) values (
    v_app.applicant_id, v_app.applicant_discord_id, auth.uid(), public.current_montresique_discord_id(),
    'Montresique Staff Team',
    'Staff application ' || v_new_status,
    'Hi ' || v_name || E'!\n\nYour application for ' || v_app.role || ' has been ' || v_new_status || '. Thank you for applying to Montresique.',
    'application_decision', v_app.id
  );

  return jsonb_build_object('id', v_app.id, 'status', v_new_status);
end;
$$;

revoke all on function public.sync_montresique_profile(text, text) from public, anon;
revoke all on function public.get_montresique_mail_recipients() from public, anon;
revoke all on function public.send_montresique_mail(uuid, text, text) from public, anon;
revoke all on function public.deliver_montresique_welcome_mail() from public, anon;
revoke all on function public.mark_montresique_mail_read(uuid) from public, anon;
revoke all on function public.review_staff_application(uuid, text) from public, anon;
grant execute on function public.sync_montresique_profile(text, text) to authenticated;
grant execute on function public.get_montresique_mail_recipients() to authenticated;
grant execute on function public.send_montresique_mail(uuid, text, text) to authenticated;
grant execute on function public.deliver_montresique_welcome_mail() to authenticated;
grant execute on function public.mark_montresique_mail_read(uuid) to authenticated;
grant execute on function public.review_staff_application(uuid, text) to authenticated;

-- Private bucket for applicant work samples. The first path segment is the
-- authenticated Supabase UUID; signed URLs are generated only after RLS checks.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'staff-application-files',
  'staff-application-files',
  false,
  5242880,
  array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
)
on conflict (id) do update set
  name = excluded.name,
  public = false,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

grant select, insert, delete on storage.objects to authenticated;
drop policy if exists staff_application_files_owner_upload on storage.objects;
create policy staff_application_files_owner_upload
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'staff-application-files'
    and (storage.foldername(name))[1] = auth.uid()::text
  );
drop policy if exists staff_application_files_owner_or_admin_read on storage.objects;
create policy staff_application_files_owner_or_admin_read
  on storage.objects for select to authenticated
  using (
    bucket_id = 'staff-application-files'
    and ((storage.foldername(name))[1] = auth.uid()::text or public.is_montresique_admin())
  );
drop policy if exists staff_application_files_owner_unlinked_delete on storage.objects;
create policy staff_application_files_owner_unlinked_delete
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'staff-application-files'
    and (storage.foldername(name))[1] = auth.uid()::text
    and not exists (
      select 1 from public.staff_applications as a
      where storage.objects.name = any(a.work_image_paths)
    )
  );

-- Supabase Realtime can notify an open admin panel when a new application lands.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'staff_applications'
     ) then
    alter publication supabase_realtime add table public.staff_applications;
  end if;
end;
$$;
