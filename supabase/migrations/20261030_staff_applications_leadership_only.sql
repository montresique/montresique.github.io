-- Only Leadership members may open or close staff application submissions.
-- This is separate from application review access, which remains available to admins.

create or replace function public.is_montresique_leadership()
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
      and tm.section = 'leadership'
      and coalesce(tm.roles::text, '') not in ('', '{}', '[]', 'null')
  );
$$;

revoke all on function public.is_montresique_leadership() from public, anon;
grant execute on function public.is_montresique_leadership() to authenticated;

drop policy if exists staff_application_settings_admin_update
  on public.staff_application_settings;
drop policy if exists staff_application_settings_leadership_update
  on public.staff_application_settings;
create policy staff_application_settings_leadership_update
  on public.staff_application_settings for update to authenticated
  using (public.is_montresique_leadership())
  with check (public.is_montresique_leadership());
