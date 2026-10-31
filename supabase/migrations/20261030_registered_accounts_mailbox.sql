-- Include every active, non-anonymous Supabase Auth account in the admin directory
-- and in the Montresique Mail recipient list, whether or not its profile has synced.

create or replace function public.get_montresique_registered_accounts()
returns table (
  user_id uuid,
  discord_user_id text,
  username text,
  last_seen timestamptz,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  if not public.is_montresique_admin() then
    raise exception 'Admin access required';
  end if;

  return query
    select
      u.id as user_id,
      coalesce(p.discord_user_id, d.provider_id, l.discord_user_id) as discord_user_id,
      coalesce(
        nullif(btrim(p.username), ''),
        nullif(btrim(l.username), ''),
        nullif(btrim(d.identity_data ->> 'username'), ''),
        nullif(btrim(d.identity_data ->> 'global_name'), ''),
        nullif(btrim(d.identity_data ->> 'full_name'), ''),
        nullif(btrim(d.identity_data ->> 'name'), ''),
        nullif(btrim(u.raw_user_meta_data ->> 'username'), ''),
        nullif(btrim(u.raw_user_meta_data ->> 'full_name'), ''),
        nullif(btrim(u.raw_user_meta_data ->> 'name'), ''),
        'Account ' || left(u.id::text, 8)
      ) as username,
      coalesce(greatest(p.last_seen, l.last_login_at, u.last_sign_in_at), u.created_at) as last_seen,
      u.created_at
    from auth.users as u
    left join public.montresique_profiles as p on p.user_id = u.id
    left join lateral (
      select i.provider_id, i.identity_data
      from auth.identities as i
      where i.user_id = u.id and i.provider = 'discord'
      order by i.updated_at desc nulls last, i.created_at desc nulls last
      limit 1
    ) as d on true
    left join lateral (
      select sl.discord_user_id, sl.username, sl.last_login_at
      from public.site_logins as sl
      where sl.discord_user_id = coalesce(p.discord_user_id, d.provider_id)
      order by sl.last_login_at desc nulls last
      limit 1
    ) as l on true
    where u.deleted_at is null
      and not coalesce(u.is_anonymous, false)
    order by username asc, last_seen desc nulls last, u.created_at asc;
end;
$$;

create or replace function public.get_montresique_mail_recipients()
returns table (user_id uuid, discord_user_id text, username text, last_seen timestamptz)
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
begin
  return query
    select a.user_id, a.discord_user_id, a.username, a.last_seen
    from public.get_montresique_registered_accounts() as a
    order by a.username asc, a.last_seen desc nulls last;
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
  v_recipient record;
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

  select a.user_id, a.discord_user_id, a.username
  into v_recipient
  from public.get_montresique_registered_accounts() as a
  where a.user_id = p_recipient_user_id;
  if not found then
    raise exception 'Recipient account not found';
  end if;

  select * into v_sender
  from public.montresique_profiles
  where user_id = auth.uid();

  insert into public.montresique_mail (
    recipient_user_id, recipient_discord_id, sender_user_id, sender_discord_id,
    sender_name, subject, body, kind
  ) values (
    v_recipient.user_id, v_recipient.discord_user_id, auth.uid(), public.current_montresique_discord_id(),
    coalesce(nullif(v_sender.username, ''), 'Montresique Developer'),
    btrim(p_subject), btrim(p_body), 'direct'
  ) returning id into v_id;

  return v_id;
end;
$$;

revoke all on function public.get_montresique_registered_accounts() from public, anon;
revoke all on function public.get_montresique_mail_recipients() from public, anon;
revoke all on function public.send_montresique_mail(uuid, text, text) from public, anon;
grant execute on function public.get_montresique_registered_accounts() to authenticated;
grant execute on function public.get_montresique_mail_recipients() to authenticated;
grant execute on function public.send_montresique_mail(uuid, text, text) to authenticated;
