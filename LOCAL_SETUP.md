# SecureVote: independent Windows local testing

This guide targets committed application `1012a1fe937f2266cfbf11573a4b6f5517c532b3`.
Production preparation is separate and uncommitted. Each tester uses their own
laptop, secrets, database, mailbox and passkeys. Do not copy the owner's .env,
database, credentials, voter records or authenticator material.

## 1. Prerequisites

- Git for Windows and access to the repository (if private, use your own GitHub account).
- 64-bit Python 3.13 with the Python launcher (`py`). Django 6.0 supports Python
  3.12–3.14; this project was tested here with Python 3.13.5.
- MySQL Community Server 8.4 LTS, running locally, plus the `mysql` command-line
  client. Django 6.0 supports MySQL 8.0.11+; do not substitute older MySQL/MariaDB
  bundled with an unrelated stack. Use InnoDB and strict SQL mode.
- A current Edge or Chrome browser and Windows Hello configured with a PIN or
  biometric method. The application requests a platform authenticator with user
  verification; a laptop without a working platform authenticator may not finish
  the passkey/voting flow. Firefox can be tested additionally; record browser/OS
  versions and authenticator behavior instead of assuming identical UI.
- Your own SMTP account/provider with authenticated sending enabled and permission
  to send to your test inboxes. No owner credentials are needed.

Official references: [Python Windows](https://www.python.org/downloads/windows/),
[Django Python support](https://docs.djangoproject.com/en/6.0/releases/6.0/),
[Django MySQL notes](https://docs.djangoproject.com/en/6.0/ref/databases/#mysql-notes),
[Windows WebAuthn](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/webauthn-apis).

## 2. Clone the exact application revision

Run in a new PowerShell window. Choose a parent folder you own; the following
uses Documents. Do not run these commands inside an existing project checkout.

```powershell
Set-Location ([Environment]::GetFolderPath('MyDocuments'))
git clone https://github.com/tlounuzy-dot/OnlineVotingSystem.git SecureVote-local
Set-Location .\SecureVote-local
git switch --detach 1012a1fe937f2266cfbf11573a4b6f5517c532b3
git rev-parse HEAD
git status --short
Test-Path .\manage.py
```

Expected: the exact hash above, clean status, and True for manage.py. The remote
repository root already contains manage.py; do not append a second
OnlineVotingSystem directory. Detached HEAD deliberately fixes the test revision.
These two handoff documents are newer than that revision; obtain them separately
until they are committed, or use the later documentation-only revision agreed by
the group. Do not run the mobile tunnel launcher for laptop-only testing.

## 3. Create and use a virtual environment

```powershell
py -3.13 --version
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

All commands below use the venv interpreter explicitly, so PowerShell activation
or execution-policy changes are unnecessary. The committed requirements include
Django, PyMySQL, WebAuthn and cryptography. PyMySQL is installed as MySQLdb by the
project package; do not install mysqlclient merely to resolve the adapter name.
cryptography supplies MySQL caching_sha2_password/RSA support. Requirements have
ranges for some dependencies, so save a local `pip freeze` listing with your test
report for reproducibility; do not change project requirements during testing.

## 4. Create a separate local MySQL database and user

Use MySQL's client in interactive mode, which prompts for the administrator
password rather than putting it on the command line:

```powershell
mysql --host=127.0.0.1 --port=3306 --user=root --password
```

If mysql is not on PATH, use its installed location, for example:

```powershell
& 'C:\Program Files\MySQL\MySQL Server 8.4\bin\mysql.exe' --host=127.0.0.1 --port=3306 --user=root --password
```

Inside that client, first check for name conflicts:

```sql
SELECT VERSION(), @@default_storage_engine, @@sql_mode;
SHOW DATABASES LIKE 'securevote_group_test';
SELECT User, Host FROM mysql.user WHERE User = 'securevote_tester';
```

If either name already exists, stop and select new names; do not drop or reuse
an existing database/user. In the SQL below, replace the bracketed password with
your own generated password before executing; it is a placeholder, not a default.
Enter it only in your private session and do not share SQL history/screenshots.

```sql
CREATE DATABASE securevote_group_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'securevote_tester'@'localhost' IDENTIFIED BY '<YOUR_OWN_GENERATED_DATABASE_PASSWORD>';
GRANT ALL PRIVILEGES ON securevote_group_test.* TO 'securevote_tester'@'localhost';
EXIT;
```

No global grants are needed for manual testing. The user needs schema privileges
on this empty test database because migrations create/alter tables. Verify its
login with a password prompt:

```powershell
mysql --host=127.0.0.1 --port=3306 --user=securevote_tester --password securevote_group_test
```

Exit after confirming connection. If MySQL reports a different host identity,
ask your local administrator to create the matching loopback-only user grant;
do not use a `%` host or disable authentication.

## 5. Create your own ignored .env

Only in this fresh clone:

```powershell
if (Test-Path .env) { throw 'An .env already exists. Inspect it privately; do not overwrite it.' }
Copy-Item .env.example .env
git check-ignore .env
notepad .env
```

The committed example has obsolete INFOBIP/TWILIO entries: remove those from
your private copy or leave them blank; they are unused. OTP is email-only.
Keep these local settings in .env, replacing the two secret placeholders and
database password with your own values:

```dotenv
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:8000
DJANGO_SECRET_KEY=<YOUR_GENERATED_DJANGO_SECRET>
VOTE_ENCRYPTION_KEY=<YOUR_GENERATED_FERNET_KEY>
DB_ENGINE=django.db.backends.mysql
DB_NAME=securevote_group_test
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=securevote_tester
DB_PASSWORD=<YOUR_OWN_GENERATED_DATABASE_PASSWORD>
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:8000
DJANGO_TRUST_X_FORWARDED_PROTO=False
DJANGO_SECURE_COOKIES=False
OTP_EXPIRY_SECONDS=300
OTP_MAX_ATTEMPTS=5
OTP_RESEND_COOLDOWN_SECONDS=60
```

Loopback HTTP uses development cookies; no proxy is involved. This does not
change hosted security. On a checkout with production preparation, also set
`DJANGO_ENV=development`. Do not set production mode for this workflow.

To generate and insert secrets directly into this private .env without displaying
them in the terminal, run the following once after saving the template above:

```powershell
@'
from pathlib import Path
from django.core.management.utils import get_random_secret_key
from cryptography.fernet import Fernet
p = Path('.env')
lines = p.read_text(encoding='utf-8-sig').splitlines()
values = {'DJANGO_SECRET_KEY': get_random_secret_key(),
          'VOTE_ENCRYPTION_KEY': Fernet.generate_key().decode()}
for key in values:
    if sum(line.startswith(key + '=') for line in lines) != 1:
        raise SystemExit('Expected exactly one entry for ' + key)
p.write_text('\n'.join(key + '=' + values[key] if key in values else line
                       for line in lines for key in [line.split('=', 1)[0]]) + '\n', encoding='utf-8')
'@ | .\.venv\Scripts\python.exe -
```

Keep these keys stable during testing. Changing the Fernet key makes earlier
encrypted choices unreadable. The simple .env loader supports KEY=VALUE, optional
outer quotes, and full-line comments; it does not expand variables or strip
inline comments. Save UTF-8 without BOM. Process environment variables take
precedence over .env. Use a fresh shell if tunnel/hosting overrides were set.

## 6. Configure your own email delivery

For actual inbox testing, explicitly use SMTP in your .env:

```dotenv
DJANGO_EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
DJANGO_DEFAULT_FROM_EMAIL=<YOUR_PROVIDER_VERIFIED_SENDER_EMAIL>
EMAIL_HOST=<YOUR_PROVIDER_SMTP_HOST>
EMAIL_PORT=587
EMAIL_HOST_USER=<YOUR_OWN_SMTP_USERNAME>
EMAIL_HOST_PASSWORD=<YOUR_OWN_SMTP_OR_APP_PASSWORD>
EMAIL_USE_TLS=True
EMAIL_USE_SSL=False
EMAIL_TIMEOUT=10
```

Use your provider's documented host/port/security settings. For implicit TLS on
465 use EMAIL_USE_SSL=True and EMAIL_USE_TLS=False; never enable both. Use an app
password when required, and authenticate/verify the sender as your provider
requires. Keep credentials in .env only. SMTP must support username/password
authentication; this committed backend does not implement OAuth-only providers.
The uncommitted Brevo backend is not part of 1012a1f.

Register using a mailbox you control (or a provider-supported alias). Synthetic
identity fields still need a real controlled mailbox for inbox tests. Never send
OTP mail to invented third-party addresses. An explicit console backend can test
workflow logic locally, but it prints codes to the terminal and does not count
as inbox delivery evidence. Do not share those terminal logs. Do not silently
substitute console delivery when SMTP fails.

## 7. Migrate, initialize roles, and start

Confirm DB_NAME identifies your new empty test database before running migrations.
Do not run makemigrations to repair setup and do not edit migration files.

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe manage.py migrate --plan
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py showmigrations
.\.venv\Scripts\python.exe manage.py seed_roles
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

Create an administrator with a test name, controlled email and private strong
password. seed_roles creates Admin/Voter roles idempotently, not voters/elections.
Open **http://localhost:8000/** (not 127.0.0.1 in the browser). Use `/login/` for
the application and `/admin/` for Django administration. Keep the server bound
to loopback. DEBUG=True serves tracked static files through runserver; no
collectstatic, Gunicorn or hosting account is needed for this local workflow.

Register voters normally. Successful email OTP changes a pending user to active
and their voter profile to verified. Login then requires the passkey step for
voter access. Never mark users verified manually to bypass the flow.

## 8. Passkeys on localhost

Use the same exact `http://localhost:8000` origin throughout registration and
authentication. Localhost is a browser secure-context exception for WebAuthn.
127.0.0.1, a different port, a LAN IP and a tunnel hostname are different origins;
do not switch among them. This setup is for each laptop independently, not
cross-device access over Wi-Fi.

Enroll Windows Hello in Windows Settings before testing. Register a new local
passkey through the app after OTP activation; authenticate when prompted and
repeat after logout. Credentials from the owner's laptop, a previous tunnel or
the eventual hosted domain are not reusable assumptions. Do not export private
keys, enable test authenticator bypasses or disable user verification.

Reference: [MDN secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts).

## 9. Optional automated tests on MySQL

The normal test runner creates and deletes `test_securevote_group_test`, separate
from the manual database. Only proceed if this test database name is unused.
Ask the local administrator to grant the same local user privileges on that
specific test database (no wildcard/global grant):

```sql
GRANT ALL PRIVILEGES ON test_securevote_group_test.* TO 'securevote_tester'@'localhost';
```

Then run:

```powershell
.\.venv\Scripts\python.exe manage.py test --parallel 1
```

Do not use --noinput to replace an existing database. If prompted to delete an
existing test database, answer no and investigate. Expected at exact 1012a1f:
94 tests (the later 101-test report includes uncommitted deployment tests).
Never point test settings at an owner's or shared production database.

## Troubleshooting

| Symptom | Safe action |
| --- | --- |
| py -3.13 unavailable / Django installation fails | Install matching 64-bit Python; confirm `py --list`; use the venv interpreter. Python 3.10/3.11 cannot run Django 6.0. |
| Wheel/dependency installation fails | Upgrade pip in the venv, check internet/proxy and Python architecture; capture package/error names without credentials. Avoid arbitrary untrusted wheels. |
| MySQL 2003 connection refused | Start the intended MySQL Windows service; check DB_HOST/DB_PORT and `Test-NetConnection 127.0.0.1 -Port 3306`. |
| MySQL 1045 denied / 1049 unknown database | Check your private password, host-specific grant and new database name. Confirm via mysql's password prompt. |
| RSA/cryptography authentication error | Verify cryptography installed inside this venv with pip show; use the committed requirements, retaining MySQL's authentication security. |
| SQLite ascii_bin error | Explicitly set DB_ENGINE to MySQL. An ordinary SQLite installation is blocked by an existing MySQL-specific migration. |
| Pending migrations / missing table | Confirm database identity privately, run migrate then showmigrations on your own test database. Never fake migrations, flush, drop tables or edit applied migrations. |
| Voter role missing | Run seed_roles after migrate. |
| SMTP authentication/sender/timeout error | Verify provider sending approval, app-password policy, sender, TLS/SSL mode and outbound port. Check junk folder; never paste credentials or OTPs into reports. |
| CSRF 403 / redirect loop / DisallowedHost | Use localhost:8000, restart after .env edits, clear only this site's cookies, use a fresh shell without tunnel/production overrides. Keep CSRF enabled. |
| Passkey NotAllowedError / SecurityError | Confirm exact origin/RP, Windows Hello enrollment, browser support and prompt completion before expiry. Record cancellation separately from application failure. |
| Passkey from another origin fails | Register a new credential on this local origin through the normal flow. Do not reuse tunnel/hosted credentials. |
| CSS/JS absent | Use DEBUG=True, venv runserver and the repository root containing manage.py; confirm /static/css/site.css returns 200. |
| Voting unavailable | Confirm active/verified voter, current passkey session, active election within its date window and approved candidate. Do not bypass guards. |
| Vote encryption configuration error | Generate the local Fernet key as above before voting; never use the example placeholder. |

Report sanitized errors and environment versions. Do not upload .env, database
dumps, passwords, OTPs, API keys, WebAuthn credential payloads or private keys.

## Sharing only these documents later

The project owner can stage only LOCAL_SETUP.md and TESTING_CHECKLIST.md and
inspect `git diff --cached --name-only` and `git diff --cached` before committing.
Avoid `git add .`, `git add -A` and `git commit -a`, which could include production
preparation. No commit or push has been performed for this handoff.
