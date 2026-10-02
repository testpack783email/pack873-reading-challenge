alter table public.profiles
  add column if not exists must_change_password boolean not null default false;

create or replace function public.pack873_can_access_app_data()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((
    select p.active is true and p.must_change_password is false
    from public.profiles as p
    where p.id = auth.uid()
  ), false);
$$;

grant execute on function public.pack873_can_access_app_data() to anon, authenticated;

drop policy if exists pack873_password_gate_profiles_select on public.profiles;
create policy pack873_password_gate_profiles_select
  on public.profiles as restrictive for select to anon, authenticated
  using (id = auth.uid() or public.pack873_can_access_app_data());

drop policy if exists pack873_password_gate_profiles_insert on public.profiles;
create policy pack873_password_gate_profiles_insert
  on public.profiles as restrictive for insert to anon, authenticated
  with check (public.pack873_can_access_app_data());

drop policy if exists pack873_password_gate_profiles_update on public.profiles;
create policy pack873_password_gate_profiles_update
  on public.profiles as restrictive for update to anon, authenticated
  using (public.pack873_can_access_app_data())
  with check (public.pack873_can_access_app_data());

drop policy if exists pack873_password_gate_profiles_delete on public.profiles;
create policy pack873_password_gate_profiles_delete
  on public.profiles as restrictive for delete to anon, authenticated
  using (public.pack873_can_access_app_data());

drop policy if exists pack873_password_gate_reading_entries on public.reading_entries;
create policy pack873_password_gate_reading_entries
  on public.reading_entries as restrictive for all to anon, authenticated
  using (public.pack873_can_access_app_data())
  with check (public.pack873_can_access_app_data());

drop policy if exists pack873_password_gate_challenges on public.challenges;
create policy pack873_password_gate_challenges
  on public.challenges as restrictive for all to anon, authenticated
  using (public.pack873_can_access_app_data())
  with check (public.pack873_can_access_app_data());

-- No browser workflow updates profiles directly. Profile state changes are made
-- by the manage-users Edge Function using the Supabase service role.
revoke update on table public.profiles from anon, authenticated;
revoke update on table public.profiles from public;

