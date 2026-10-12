# Isolated MySQL + Brevo OTP workflow: review before execution

None of the database creation, migration, seeding, server or browser steps below
have been executed by Codex. The user confirmed receipt of the previous harmless
Django/Brevo email. This plan verifies real OTP workflows next, with synthetic data.

## Current inspected configuration

HEAD is 6b6fbc2 (documentation commit); production preparation remains uncommitted.
Effective settings inspected without a database connection:

| Setting | Current value |
| --- | --- |
| Mode | development |
| Database engine | django.db.backends.mysql |
| Database name | online_voting_db |
| Host / port | 127.0.0.1 / 3306 |
| Email backend | django.core.mail.backends.smtp.EmailBackend |
| Email timeout | 10 seconds |
| Brevo key in inspected process/settings | absent |
| WebAuthn RP / origin | localhost / http://localhost:8000 |
| OTP expiry / attempts / resend cooldown | 300 seconds / 5 / 60 seconds |

Database username/password are configured; their values were not displayed.
Development loads .env using os.environ.setdefault, so explicit process values
take precedence. Production instead requires AIVEN_MYSQL_* and does not load .env.
Never select production mode for this local test.

All existing migrations must run on the new empty database, including the legacy
SMS metadata migration: its existence does not enable SMS. Credential migration
0006 reads credential rows only from its selected database, which is initially
empty. No migration files need changes. seed_roles creates Admin and Voter roles
idempotently; it does not create voters or elections.

Requirements: working Python 3.13/Django 6.0.9/PyMySQL/cryptography, local MySQL
8.4 recommended (Django supports 8.0.11+, but this grant helper requires 8.0.16+
for partial_revokes), MySQL administrative authority to create one
database/user, verified Brevo sender/key, and Windows Hello plus current Edge or
Chrome for platform passkeys. No application-code blocker was found.

## 1. Common terminal preparation

Open a new dedicated PowerShell terminal. Do not start a transcript, dump process
environment, print settings, capture HTTP bodies, or share credentials. Review
each phase separately before executing it.

```powershell
Set-Location 'C:\Users\Admin\Downloads\NPRT PROJECT\OnlineVotingSystem'
if (-not (Test-Path .\manage.py)) { throw 'Wrong project directory.' }
$otpPython = if (Test-Path .\.venv\Scripts\python.exe) {
    (Resolve-Path .\.venv\Scripts\python.exe).Path
} else {
    (Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
}
function Read-OtpPrivateValue([string]$Prompt) {
    $otpSecure = Read-Host $Prompt -AsSecureString
    $otpPointer = [IntPtr]::Zero
    try {
        $otpPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($otpSecure)
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($otpPointer)
    } finally {
        if ($otpPointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($otpPointer)
        }
        $otpSecure.Dispose()
    }
}
```

The function returns directly into an assignment below, never to terminal output.
Passwords/key briefly exist in process memory to authenticate; no user/machine
environment setting or .env file is written. Keep your chosen database password
in your own password manager for future access. Do not generate/replace Brevo keys.

## 2. Explicit database/user creation (user execution only)

Names: database `securevote_otp_test`; account `securevote_otp_tester` at `localhost`.
Use a new strong dedicated password, not your existing database/admin password.
The preflight reads schema/account metadata only, never existing voter records.
It refuses an existing database or any existing account with that username.

```powershell
try {
    $env:SECUREVOTE_OTP_ADMIN_USER = Read-Host 'Local MySQL administrator username'
    $env:SECUREVOTE_OTP_ADMIN_PASSWORD = Read-OtpPrivateValue 'Local MySQL administrator password (hidden)'
    $env:SECUREVOTE_OTP_NEW_PASSWORD = Read-OtpPrivateValue 'New dedicated OTP test database password (hidden)'
    @'
import os
import sys
import pymysql
stage = 'configuration'
connection = None
try:
    password = os.environ['SECUREVOTE_OTP_NEW_PASSWORD']
    if len(password) < 16:
        raise ValueError('Use a strong password of at least 16 characters')
    stage = 'administrator connection'
    connection = pymysql.connect(host='127.0.0.1', port=3306,
        user=os.environ['SECUREVOTE_OTP_ADMIN_USER'],
        password=os.environ['SECUREVOTE_OTP_ADMIN_PASSWORD'],
        connect_timeout=10, read_timeout=10, write_timeout=10, autocommit=True)
    with connection.cursor() as cursor:
        stage = 'name-conflict preflight'
        cursor.execute('SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name=%s',
                       ('securevote_otp_test',))
        if cursor.fetchone()[0]:
            raise RuntimeError('Database already exists; stop for private inspection')
        cursor.execute('SELECT COUNT(*) FROM mysql.user WHERE User=%s', ('securevote_otp_tester',))
        if cursor.fetchone()[0]:
            raise RuntimeError('User already exists; stop for private inspection')
        cursor.execute('SELECT @@partial_revokes')
        literal_grants = bool(cursor.fetchone()[0])
        stage = 'database creation'
        cursor.execute('CREATE DATABASE `securevote_otp_test` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci')
        stage = 'dedicated user creation'
        cursor.execute("CREATE USER 'securevote_otp_tester'@'localhost' IDENTIFIED BY %s", (password,))
        stage = 'database-only privilege grant'
        schema = 'securevote_otp_test' if literal_grants else r'securevote\_otp\_test'
        cursor.execute('GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, REFERENCES '
                       f"ON `{schema}`.* TO 'securevote_otp_tester'@'localhost'")
    print('Created the isolated database and dedicated loopback account with database-only privileges.')
except Exception:
    print('Stopped during ' + stage + '. No credentials shown. If creation began, '
          'inspect partial setup privately; do not drop/reuse existing objects or blindly rerun.', file=sys.stderr)
    sys.exit(1)
finally:
    if connection is not None:
        connection.close()
'@ | & $otpPython -
    if ($LASTEXITCODE -ne 0) { throw 'Creation did not complete. Stop here.' }
} finally {
    Remove-Item Env:\SECUREVOTE_OTP_ADMIN_USER, Env:\SECUREVOTE_OTP_ADMIN_PASSWORD,
        Env:\SECUREVOTE_OTP_NEW_PASSWORD -ErrorAction SilentlyContinue
}
```

No DROP, global privileges, grant option, wildcard account host or changes to
server security are used. These grants cover current migrations and workflows;
they deliberately do not permit dropping databases or automated test-database
creation. MySQL DDL is not an atomic rollback operation: inspect a partial failure,
do not automatically delete objects. MySQL validates password policy normally.

Underscores in database-level grants can be wildcards when partial_revokes is off;
the block selects the correct literal grant form for that server setting.
[MySQL GRANT documentation](https://dev.mysql.com/doc/refman/8.4/en/grant.html).

## 3. Select isolated DB and Brevo in this terminal only

Use the dedicated password created above. Sender must be the exact bare verified
Brevo email address. Gmail EMAIL_HOST_* credentials stay untouched and unused.
The backend uses HTTPS with certificate validation, not SMTP. Local browser access
remains http://localhost:8000, the existing WebAuthn secure-context exception.

```powershell
$env:DJANGO_ENV = 'development'
$env:DJANGO_SETTINGS_MODULE = 'online_voting_system.settings'
$env:DB_ENGINE = 'django.db.backends.mysql'
$env:DB_NAME = 'securevote_otp_test'
$env:DB_HOST = '127.0.0.1'
$env:DB_PORT = '3306'
$env:DB_USER = 'securevote_otp_tester'
$env:DB_PASSWORD = Read-OtpPrivateValue 'Dedicated OTP test database password (hidden)'
$env:DJANGO_EMAIL_BACKEND = 'accounts.email_backends.BrevoEmailBackend'
$env:DJANGO_DEFAULT_FROM_EMAIL = (Read-Host 'Exact verified Brevo sender email').Trim()
$env:BREVO_API_KEY = Read-OtpPrivateValue 'Existing Brevo API key (hidden)'
$env:EMAIL_TIMEOUT = '10'
$env:DJANGO_ALLOWED_HOSTS = 'localhost,127.0.0.1'
$env:DJANGO_CSRF_TRUSTED_ORIGINS = 'http://localhost:8000'
$env:WEBAUTHN_RP_ID = 'localhost'
$env:WEBAUTHN_ORIGIN = 'http://localhost:8000'
$env:DJANGO_TRUST_X_FORWARDED_PROTO = 'False'
$env:DJANGO_SECURE_COOKIES = 'False'
$env:DJANGO_DEBUG = 'False'
$env:OTP_EXPIRY_SECONDS = '300'
$env:OTP_MAX_ATTEMPTS = '5'
$env:OTP_RESEND_COOLDOWN_SECONDS = '60'
```

DEBUG=False avoids browser debug-page exposure of submitted codes on unexpected
errors. HTTP loopback cookies and no proxy preserve the established localhost
workflow; hosted configuration remains untouched. Existing Django/encryption keys
are loaded privately from .env; do not display or replace them. This procedure
does not test voting or alter stored encrypted choices.

## 4. Identity-guarded commands

Define this helper in the same terminal. It checks configured engine/name/host/
port/user before any DB connection. It then connects with the dedicated account,
queries only DATABASE(), CURRENT_USER() and server port, and aborts on mismatch.
Each invocation rechecks identity before the requested operation.

```powershell
function Invoke-OtpDjango([string]$Action) {
    @'
import os
import sys
try:
    from django.conf import settings
    expected = {'ENGINE': 'django.db.backends.mysql', 'NAME': 'securevote_otp_test',
                'HOST': '127.0.0.1', 'PORT': '3306', 'USER': 'securevote_otp_tester'}
    db = settings.DATABASES['default']
    if settings.PRODUCTION or any(str(db.get(k, '')) != v for k, v in expected.items()):
        raise RuntimeError('Configured database identity mismatch')
    if settings.EMAIL_BACKEND != 'accounts.email_backends.BrevoEmailBackend' or not settings.BREVO_API_KEY:
        raise RuntimeError('Brevo configuration missing')
    from django.core.validators import validate_email
    validate_email(settings.DEFAULT_FROM_EMAIL)
    # Runtime-only static serving with DEBUG=False, without collectstatic or source edits.
    settings.MIDDLEWARE = list(settings.MIDDLEWARE)
    settings.MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')
    settings.WHITENOISE_USE_FINDERS = True
    settings.LOGGING = {'version': 1, 'disable_existing_loggers': False,
        'handlers': {'quiet': {'class': 'logging.NullHandler'}},
        'loggers': {name: {'handlers': ['quiet'], 'propagate': False}
                    for name in ('django.request', 'django.server', 'django.security')}}
    import django
    django.setup()
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute('SELECT DATABASE(), CURRENT_USER(), @@port')
        name, account, port = cursor.fetchone()
        if (name, account, int(port)) != ('securevote_otp_test', 'securevote_otp_tester@localhost', 3306):
            raise RuntimeError('Connected database/account identity mismatch')
        print('Verified: isolated OTP test database, dedicated localhost account, port 3306.')
        action = sys.argv[1]
        if action == 'verify-empty':
            cursor.execute('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s', (name,))
            if cursor.fetchone()[0] != 0:
                raise RuntimeError('Database is not empty; stop before first initialization')
            print('Verified: new schema contains no tables.')
    from django.core.management import call_command
    if action == 'verify-empty':
        pass
    elif action == 'check':
        call_command('check')
    elif action == 'plan':
        call_command('migrate', plan=True, database='default')
    elif action == 'migrate':
        call_command('migrate', interactive=False, database='default')
    elif action == 'seed_roles':
        call_command('seed_roles')
    elif action == 'showmigrations':
        call_command('showmigrations', database='default')
    elif action == 'consistency':
        call_command('makemigrations', check=True, dry_run=True)
    elif action == 'runserver':
        call_command('runserver', '127.0.0.1:8000', use_reloader=False)
    else:
        raise RuntimeError('Unsupported action')
except Exception:
    print('Operation stopped. No secret/error detail displayed. Check identity, grants '
          'and prerequisites privately; do not switch to the existing database.', file=sys.stderr)
    sys.exit(1)
'@ | & $otpPython - $Action
    if ($LASTEXITCODE -ne 0) { throw 'Isolated operation failed. Stop before the next command.' }
}
```

First run only the read-only verification and plan, then inspect the results:

```powershell
Invoke-OtpDjango 'verify-empty'
Invoke-OtpDjango 'check'
Invoke-OtpDjango 'plan'
```

Only after successful identity/empty-schema checks, manually run initialization:

```powershell
Invoke-OtpDjango 'migrate'
Invoke-OtpDjango 'showmigrations'
Invoke-OtpDjango 'consistency'
Invoke-OtpDjango 'seed_roles'
```

Expected: all migrations applied, no model changes, Admin/Voter roles created.
Do not use flush, fake migrations, database reset or edit migrations. The
verify-empty check is for initial setup only; it must fail after migration.

When ready for browser tests, in this same terminal:

```powershell
Invoke-OtpDjango 'runserver'
```

No reloader is used; settings/credentials remain in this server process. WhiteNoise
serves tracked static assets through finders for this process only. It must already
be installed from current requirements. Port conflicts must be resolved by stopping
your own old server; do not kill unrelated processes. Open http://localhost:8000.
Do not use 127.0.0.1 in the browser, a LAN IP, another port, or the mobile tunnel.
Use a new browser profile/private session to avoid cookies from the old database.
No administrator or manually verified voter is needed for the OTP tests.

## 5. Browser test sequence and expected results

Use fictional names, adult DOB 2000-01-01, IDs OTP-TEST-A-001 / OTP-TEST-B-001 /
OTP-TEST-C-001, and your controlled inboxes/aliases. Do not send to invented
third-party addresses, use real voter IDs or share screenshots of OTPs/passwords.

1. **Registration:** /register/, create Synthetic A with a controlled inbox and
   strong password. Request email OTP; check actual receipt, then enter it. Expected:
   activation/verified voter, no voting access without normal passkey verification.
2. **Correction and old-code invalidation:** for pending Synthetic B, use a second
   controlled address as the deliberately incorrect address. Receive but do not
   consume code A. Wait 60 seconds, choose Change email and correct to your intended
   inbox. Receive code B. Code A must fail; code B must activate the same identity.
   This controlled alias simulates a typo without mailing an unknown person. You
   can test an undeliverable typo separately, but cannot prove old-code invalidation
   if you never receive the original code.
3. **Duplicate ID/email:** logout before public registration; try registering a
   different inbox with B's fictional ID. Expected validation rejection, no second
   voter. Duplicate existing email must also be rejected. A pending-email correction
   to A's occupied email must fail; no duplicate account should be created.
4. **Resend:** use pending Synthetic C. Immediate resend blocked; after 60 seconds
   resend allowed and previous code invalidated. Entering the previous code fails.
5. **Expiry:** let C's new code sit for more than 300 seconds. Correct code must
   fail as expired. Request a new one through the UI; do not edit clocks/settings.
6. **Attempt limits:** on another fresh C code, submit an incorrect six-digit code
   different from the inbox code five times. Correct code must then be unusable;
   request a fresh code. Malformed input may be rejected by the form without an
   attempt increment; use valid six-digit incorrect input for this test.
7. **Single use:** complete C with a fresh code. Returning/replaying the completed
   verification cannot activate a second identity or reuse that code.
8. **Password recovery:** logged out, open /password-reset/ for activated A, request
   email-only OTP, confirm receipt, enter it and choose a new strong password. Old
   password fails; new password works. Recovery must not grant administrator access,
   remove passkeys or bypass the normal voter passkey step. Repeat cooldown/expiry/
   wrong-code/single-use checks for reset with fresh codes. Unknown email keeps a
   generic recovery flow. Direct new-password access without verified OTP is denied.
9. **Login/passkey:** with Windows Hello enrolled, log in as A on exact localhost
   origin; enroll a fresh platform passkey and authenticate it. Cancelled prompts
   must not grant access. Logout/login again requires passkey verification. Before
   that step, direct dashboard/voting access remains guarded. No security bypasses.

Record pass/fail/blocked, subject and approximate inbox arrival time, sanitized UI
messages, and browser/OS versions. API acceptance is not inbox receipt. Browser
authentication limitations must be reported separately from OTP failures. Capture
no OTP digits, credentials, cookie headers or credential assertion bodies.

## 6. Stop, clear secrets and restore the original workflow

Ctrl+C stops the test server. Then clear dedicated process overrides and close
this dedicated terminal (never run an existing server with partially cleared DB
settings):

```powershell
Remove-Item Env:\DB_PASSWORD, Env:\BREVO_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:\DB_ENGINE, Env:\DB_NAME, Env:\DB_HOST, Env:\DB_PORT, Env:\DB_USER,
    Env:\DJANGO_ENV, Env:\DJANGO_SETTINGS_MODULE, Env:\DJANGO_EMAIL_BACKEND,
    Env:\DJANGO_DEFAULT_FROM_EMAIL, Env:\EMAIL_TIMEOUT, Env:\DJANGO_ALLOWED_HOSTS,
    Env:\DJANGO_CSRF_TRUSTED_ORIGINS, Env:\WEBAUTHN_RP_ID, Env:\WEBAUTHN_ORIGIN,
    Env:\DJANGO_TRUST_X_FORWARDED_PROTO, Env:\DJANGO_SECURE_COOKIES, Env:\DJANGO_DEBUG,
    Env:\OTP_EXPIRY_SECONDS, Env:\OTP_MAX_ATTEMPTS, Env:\OTP_RESEND_COOLDOWN_SECONDS -ErrorAction SilentlyContinue
Remove-Item Function:\Read-OtpPrivateValue, Function:\Invoke-OtpDjango -ErrorAction SilentlyContinue
```

Restart the original SMTP/local-database workflow in a fresh terminal so unchanged
.env settings apply. Keep the isolated database/user for evidence/retesting; this
guide does not drop them. If initialization failed, review the partial objects
privately with your local MySQL administrator rather than resetting anything.

Likely blockers: existing database/user names, insufficient admin rights, MySQL
host-grant mismatch (identity check will stop), unavailable port 3306/8000,
WhiteNoise/dependency installation, unverified sender or Brevo restrictions, and
Windows Hello/browser support. No live checks of these prerequisites were executed.
