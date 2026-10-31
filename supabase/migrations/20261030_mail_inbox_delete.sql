-- Let an authenticated user remove a message from their own Montresique inbox only.
-- The recipient check prevents senders or admins from deleting another account's copy.
create or replace function public.delete_montresique_mail(p_message_id uuid)
returns boolean
language plpgsql
security definer
set search_path = public, auth, pg_temp
as $$
declare
  v_deleted integer;
begin
  if auth.uid() is null then
    raise exception 'Login required';
  end if;

  delete from public.montresique_mail
  where id = p_message_id
    and recipient_user_id = auth.uid();

  get diagnostics v_deleted = row_count;
  if v_deleted = 0 then
    raise exception 'Message not found in your inbox';
  end if;

  return true;
end;
$$;

revoke all on function public.delete_montresique_mail(uuid) from public, anon;
grant execute on function public.delete_montresique_mail(uuid) to authenticated;
