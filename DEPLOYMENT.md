# Pack 873 Reading Challenge deployment notes

The app now supports one server-managed temporary password for new and reactivated accounts. Those accounts must change it before the app loads their reading data. Users can change their password later from the header.

## Supabase setup

1. Apply `supabase/migrations/20261002000000_password_change_required.sql` to the existing project. In Supabase, run its contents in the SQL Editor, or apply the migration with the Supabase CLI.
2. Deploy `supabase/functions/manage-users/index.ts` as the `manage-users` Edge Function. It replaces the function currently used by the webpage for account creation, reactivation, deactivation, deletion, account listing, and connection checks.
3. In the Edge Function secrets, set `STANDARD_TEMP_PASSWORD` to the Pack 873 temporary password chosen in the project chat. Do not put its value in this repository, the webpage, or a deploy command that will be saved in shell history.
4. The function reads Supabase's built-in `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEYS` and `SUPABASE_SECRET_KEYS` values, with a fallback for the legacy `SUPABASE_ANON_KEY` and `SUPABASE_SERVICE_ROLE_KEY` variables.
5. Publish the updated `index.html` to the existing Cloudflare Pages site.

The migration gives existing profiles `must_change_password = false`; only new accounts and reactivated accounts are marked as needing a password change. The Edge Function never returns the shared temporary password to the browser.

## Account behavior

- Admin creates a user with name, email, and role. The Edge Function uses `STANDARD_TEMP_PASSWORD` and flags the account for a forced password change.
- Reactivating a user resets the password to the same server secret and requires another password change.
- Deactivation preserves reading history. Permanent deletion removes the user's reading entries, profile, and Auth account.
- A signed-in user can change their password from the header.


## Rank book recommendation PDFs

1. Apply `supabase/migrations/20261008000000_rank_book_recommendations.sql` in the same Supabase project before using this feature. In the Dashboard, open **SQL Editor**, paste the migration contents, and run it. It creates the private `pack873-rank-recommendations` Storage bucket and RLS policies.
2. The six files use fixed paths: `ranks/lion.pdf`, `ranks/tiger.pdf`, `ranks/wolf.pdf`, `ranks/bear.pdf`, `ranks/webelos.pdf`, and `ranks/arrow-of-light.pdf`.
3. Sign into the app as Admin, click **Book Recommendations** in the Current Challenge card, choose a rank, select a PDF (up to 15 MB), and click **Upload / Replace PDF**. To update a document's contents, revise the PDF outside the app and upload the replacement for that rank. Use **Remove PDF** to remove a recommendation.
4. Signed-in readers can choose any rank and download its PDF. The bucket is private; download links expire after one hour. Only active Admins can upload, replace, or remove files.

