# One-time hosted application administrator

Prepared for review only. Do not run until the workflow and helper have been reviewed.
Target: Aiven `securevote_test`, authenticated account `securevote_app`, port `25586`.
No local `.env`, local MySQL, Render setting, public endpoint, migration or existing
voter/election/vote is changed by this procedure.

## What it does

The manual workflow runs on GitHub-hosted Ubuntu with Python 3.13. It checks out
the reviewed tool separately from the exact application commit deployed on Render.
It installs that application's requirements without provisioning secrets present.
The final step alone receives credentials. The helper parses selected literal Django
settings without importing settings.py or loading .env. It uses a command-only random
SECRET_KEY, not the Render secret or vote-encryption key.

It requires certificate-chain AND hostname verification, TLS 1.2/1.3, the exact database
and authenticated MySQL user, InnoDB account tables, consistent/current migrations
(including no unknown applied migrations), and the existing Admin role. Missing or
unexpected configuration causes a sanitized failure, without printing exception details.

Inside a transaction it locks the Admin role, rejects any existing Admin-role, staff
or superuser account (including inactive accounts), rejects an existing email ignoring
case, runs Django password validators and model validation, rechecks database/TLS,
then uses `User.objects.create_user`. The only intended data write is one user INSERT:
`full_name='SecureVote Demo Administrator'`, active status, `is_active=True`,
`is_staff=True`, `is_superuser=False`. No Voter profile is created. A second run refuses.
The role lock serializes copies of this tool; do not provision administrators through
another tool concurrently. No database-wide uniqueness constraint for Admin is added.

This is the privileged out-of-band administrator bootstrap, not public registration.
It does not send a registration OTP or grant unrestricted Django superuser permissions.
Existing website OTP/passkey/CSRF/authentication behavior is unchanged.

## Review and prerequisites

1. Confirm `main` is the repository's default branch. The workflow only permits main.
2. In Render, identify the currently LIVE deployment's full 40-character Git commit SHA.
   Do not assume it is the newest GitHub commit. Review that commit's requirements,
   user manager, model and app startup hooks. The helper currently requires Django 6.0.9.
3. Obtain the actual Aiven service DNS name ending in `.aivencloud.com`, the
   `securevote_app` password and downloaded CA certificate for that service. Port 25586
   is intentionally fixed. Use the PEM certificate contents, not its Windows filename,
   not a private key and not base64 encoding.
4. Confirm Aiven accepts network traffic from the chosen GitHub-hosted runner. Render
   connectivity does not prove this. Standard runner egress addresses vary; this job
   neither changes an IP allowlist nor opens public access. If access is restricted,
   stop and arrange an approved network path (for example a supported GitHub-hosted
   runner with static egress); do not disable TLS or allow all IPs as a workaround.
5. The database account needs reads of migration/account metadata and roles/users,
   the ability to lock the Admin role, and INSERT on accounts_user. This tool does
   not need schema changes, GRANT, or global administration. Existing service-account
   privileges may be broader; exposing that credential to Actions is a trust decision.
6. Choose a new, unused email for an inbox you control and a strong unique password
   in your password manager. The normal Django password validators must accept it.
7. Only trusted maintainers should edit workflow/application code or approve this run.
   Do not enable Actions step/runner debug logging or add environment/SQL dumps.

## Add the files after review (not performed automatically)

The eventual reviewed commit should include only these four files:

- `.github/workflows/provision-demo-admin.yml`
- `scripts/provision_demo_admin.py`
- `scripts/test_provision_demo_admin.py`
- `ONE_TIME_ADMIN_ACTION.md`

Do not stage .env, CA files, database exports, passwords, or unrelated local edits.
The workflow must exist on the default branch before manual dispatch is available.
Adding it to main can trigger Render's existing auto-deploy independently of Actions.
When later authorized to commit/merge these tooling-only files, include `[skip render]`
in the actual commit/merge message to skip Render auto-deployment without changing its
configuration. Confirm Render still shows the expected live commit before proceeding.
Use the same precaution for the eventual removal commit. Never skip review of the
commit actually being merged.

## Configure GitHub environment and secrets

1. Repository **Settings > Environments > New environment**: create
   `securevote-admin-provision` before running anything.
2. Restrict deployment branches to the **Branch** `main` (not tags). Where available,
   add a required reviewer, prevent self-review and disallow protection-rule bypass.
   GitHub plan/repository visibility controls availability. If environment secrets or
   branch restrictions are unavailable, stop for review rather than moving secrets to
   broadly available repository scope. Where required reviewers are unavailable, get
   a separate review before dispatch and limit repository write access to trusted users.
3. Under **Environment variables > Add variable**, add:

   | Variable | Value |
   | --- | --- |
   | `SV_DEPLOYED_SHA` | Full lowercase 40-character SHA verified in Render |

4. Under **Environment secrets > Add secret**, add each separately:

   | Secret | Value supplied privately by the operator |
   | --- | --- |
   | `SV_AIVEN_HOST` | Exact Aiven service DNS hostname, no scheme or port |
   | `SV_AIVEN_PASSWORD` | Existing `securevote_app` database password |
   | `SV_AIVEN_CA_PEM` | Complete downloaded CA PEM, including BEGIN/END lines and real newlines |
   | `SV_ADMIN_EMAIL` | Unused email address for your demonstration administrator |
   | `SV_ADMIN_PASSWORD` | Strong unique administrator password |

   No DB name/user/port secret is needed: these targets are fixed in the helper.
   Do not supply Brevo keys, Render tokens, Django site secrets or encryption keys.
   Do not put email or passwords in dispatch inputs, commits, issues or chat.

## Trigger exactly once, after approval

1. GitHub repository **Actions > One-time SecureVote administrator > Run workflow**.
2. Select branch **main**.
3. Set `deployed_sha` to the exact same full SHA as `SV_DEPLOYED_SHA`.
4. Set `confirmation` to `CREATE ONE DEMO ADMIN IN securevote_test`.
5. Click **Run workflow**. If configured, the reviewer must inspect and approve the
   environment job. The helper then proceeds from checks to INSERT without another pause.
6. Expected safe log messages identify only the fixed database/account/TLS verification
   and successful creation of one active application administrator. Credentials, hashes,
   email addresses and voter data are never intentionally logged or uploaded as artifacts.
7. On a failure, use the reported stage. Wrong CA/host, blocked port, missing role,
   schema mismatch, existing account/admin, weak password or missing secrets can stop it.
   Do not add exception dumps. A failure, timeout or cancellation during COMMIT can
   leave the account created: privately try the intended login before retrying. Never
   delete/overwrite an account just to make this tool succeed.

## Verify access and remove temporary capability

1. Open a private window at `https://securevote-demo.onrender.com/login/` and log in
   using the new credentials. Expect `/admin/dashboard/`; inspect elections, candidates
   and reports without altering existing records. This account is for the SecureVote
   application dashboard; it has no blanket superuser rights in Django's `/admin/`.
2. Disable this workflow from its Actions menu immediately after successful verification.
3. Delete all five environment secrets and `SV_DEPLOYED_SHA`, or delete the dedicated
   `securevote-admin-provision` environment after confirming no run remains active.
   Deleting the GitHub copy does NOT revoke/change the Aiven password used by Render.
   Do not rotate shared credentials or change Render configuration as part of cleanup.
4. In a separately reviewed cleanup commit remove the workflow, helper, offline test
   and this one-time guide. Include `[skip render]` if no redeployment is intended.
   Keep only a nonsensitive audit note of who approved, the run ID and successful outcome.
5. Remove only any temporary network access you explicitly arranged. Keep the
   administrator password in your password manager. Neither removing the workflow nor
   deleting secrets deletes the administrator or any hosted data.

## Offline validation

Run from the project root in a fresh Python 3.13 / Django 6.0.9 process:

```powershell
python -B -m unittest discover -s scripts -p test_provision_demo_admin.py -v
```

Tests configure only an in-memory SQLite database; they do not import .env, connect to
MySQL or run the provisioning entry point against Aiven. Real manager/password validation
and transaction rollback are exercised; MySQL metadata/TLS results are mocked. A test-only
collation handles a historical MySQL migration. Passing these tests does not establish
GitHub runner reachability, real MySQL locking, TLS handshake or hosted account creation.

References: [manual dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow),
[GitHub environments and plan limits](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments),
[Render skip-deploy messages](https://render.com/docs/deploys#skipping-an-auto-deploy).
