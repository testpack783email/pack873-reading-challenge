-- Private, per-rank Pack 873 book recommendation PDFs.
-- Files are stored at: ranks/<Scout rank>.pdf
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'pack873-rank-recommendations',
  'pack873-rank-recommendations',
  false,
  15728640,
  array['application/pdf']::text[]
)
on conflict (id) do update
set public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists pack873_rank_recommendations_read on storage.objects;
create policy pack873_rank_recommendations_read
  on storage.objects
  for select
  to authenticated
  using (
    bucket_id = 'pack873-rank-recommendations'
    and public.pack873_can_access_app_data()
  );

drop policy if exists pack873_rank_recommendations_admin_insert on storage.objects;
create policy pack873_rank_recommendations_admin_insert
  on storage.objects
  for insert
  to authenticated
  with check (
    bucket_id = 'pack873-rank-recommendations'
    and public.is_admin()
    and public.pack873_can_access_app_data()
  );

drop policy if exists pack873_rank_recommendations_admin_update on storage.objects;
create policy pack873_rank_recommendations_admin_update
  on storage.objects
  for update
  to authenticated
  using (
    bucket_id = 'pack873-rank-recommendations'
    and public.is_admin()
    and public.pack873_can_access_app_data()
  )
  with check (
    bucket_id = 'pack873-rank-recommendations'
    and public.is_admin()
    and public.pack873_can_access_app_data()
  );

drop policy if exists pack873_rank_recommendations_admin_delete on storage.objects;
create policy pack873_rank_recommendations_admin_delete
  on storage.objects
  for delete
  to authenticated
  using (
    bucket_id = 'pack873-rank-recommendations'
    and public.is_admin()
    and public.pack873_can_access_app_data()
  );
