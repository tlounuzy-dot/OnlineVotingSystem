# SecureVote hosted group testing

This prepares the existing system for testing with synthetic accounts. It is not
a secret-ballot election system: Vote retains voter/candidate relations and IP
addresses alongside encrypted_choice. Restrict staff access and database access.
No migrations or local data need changing for this preparation.

## Render

Use a Linux Python web service with Python 3.13, Django 6.0.9 and Gunicorn 26.1.0.
Set Render's PYTHON_VERSION to the chosen supported 3.13 patch release explicitly.
The repository has manage.py at its root: leave Render's Root Directory blank
(repository root), rather than using the local checkout folder name.
Gunicorn is installed on Linux and intentionally skipped on Windows.

Build: `pip install -r requirements.txt && python manage.py collectstatic --noinput`

The requirements pin Django within the 6.0 series and Gunicorn to verified PyPI
releases supporting Python 3.13. Revalidate dependency updates in an isolated
environment before changing pins; do not upgrade to Django 6.1 implicitly.

Start: `gunicorn online_voting_system.wsgi:application --bind 0.0.0.0:$PORT --workers 2 --timeout 60 --access-logfile /dev/null --error-logfile -`

Pre-deploy/release command: `python manage.py migrate --noinput`

Run migrations once per release, never from each worker. If the selected plan
does not support a pre-deploy command, run migrations in its service shell before
opening testing. Back up Aiven first for later releases. Never point hosted
settings at local MySQL or import real voter records.

Render terminates HTTPS. Proxy trust is safe only when all application traffic
passes through Render's trusted proxy, which sets X-Forwarded-Proto. Confirm this
before enabling service access. Secure redirects must not loop.

## Environment variables

Set these in Render's environment UI; do not place values in source or .env.example.
Production deliberately does not load .env and does not use local DB_* variables.

| Name | Required value/purpose |
| --- | --- |
| DJANGO_ENV | `production` |
| DJANGO_DEBUG | `False` (default in production) |
| DJANGO_SECRET_KEY | Independently generated secret, at least 50 characters |
| VOTE_ENCRYPTION_KEY | Generated Fernet key; retain securely with backups |
| DJANGO_ALLOWED_HOSTS | Exact final Render hostname, comma-separated if needed; no wildcard |
| DJANGO_CSRF_TRUSTED_ORIGINS | Exact HTTPS origin(s), no trailing slash |
| WEBAUTHN_RP_ID | Exact final hostname, without scheme or port |
| WEBAUTHN_ORIGIN | `https://` followed by that exact hostname, without trailing slash |
| AIVEN_MYSQL_HOST | Aiven service hostname from connection details |
| AIVEN_MYSQL_PORT | Aiven service port |
| AIVEN_MYSQL_DATABASE | Separate hosted test database name |
| AIVEN_MYSQL_USER | Dedicated application database user |
| AIVEN_MYSQL_PASSWORD | Dedicated database password |
| AIVEN_MYSQL_SSL_CA | Absolute path to Aiven CA certificate, e.g. `/etc/secrets/aiven-ca.pem` |
| DJANGO_EMAIL_BACKEND | `accounts.email_backends.BrevoEmailBackend` |
| DJANGO_DEFAULT_FROM_EMAIL | Brevo verified sender email address |
| BREVO_API_KEY | Brevo transactional API key, not an SMTP key |

Optional controls: `DJANGO_SECURE_COOKIES`, `DJANGO_SECURE_SSL_REDIRECT`, and
`DJANGO_TRUST_X_FORWARDED_PROTO` default to True in production and cannot be
disabled there. `DJANGO_SECURE_HSTS_SECONDS` defaults to 3600; use 0 only during
initial HTTPS troubleshooting, then restore a positive duration. HSTS subdomain
and preload flags are deliberately off. `EMAIL_TIMEOUT` defaults to 10 seconds
(range 1–60). `WEBAUTHN_RP_NAME` is optional. Existing `OTP_EXPIRY_SECONDS` (300),
`OTP_MAX_ATTEMPTS` (5), and `OTP_RESEND_COOLDOWN_SECONDS` (60) remain supported.

Consequently, check --deploy reports security.W005 and security.W021. These are
deliberate policy warnings for initial group testing: retain the one-hour HSTS
policy while verifying HTTPS. Enable subdomain coverage or preload only after
confirming domain ownership, every affected host's HTTPS support, and the long-term
commitment. Do not change those flags merely to silence the checks.

## Aiven and Brevo prerequisites

Download the CA certificate from the intended Aiven service and mount it as a
Render secret file at AIVEN_MYSQL_SSL_CA. Never disable certificate or hostname
verification. Configure Aiven network access to permit the Render service; use a
separate database/user and least privilege, including migration privileges during
release. Ensure backups, connection limits, and the selected region suit testing.
The existing PyMySQL adapter uses ssl_ca, ssl_verify_cert, and ssl_verify_identity.

In Brevo, verify the sender and authenticate its domain (SPF/DKIM as instructed
by Brevo); enable transactional sending and confirm quotas/account approval.
Set the API key only in Render. The backend sends HTTPS requests to the fixed
Brevo endpoint with a timeout, rejects redirects, and does not log request bodies
or response bodies. No automatic retry is performed because a timeout can follow
successful acceptance. A failed issue invalidates that OTP; the user may request
another code. Provider acceptance does not guarantee inbox delivery.

## Release verification

1. Finalize the exact HTTPS domain before registering passkeys. Existing localhost
   or tunnel passkeys do not transfer to the hosted RP. A later domain change can
   require new credentials; choose the domain before inviting testers.
2. Run `python manage.py check --deploy`, `python manage.py makemigrations --check --dry-run`,
   and the serial test suite against an isolated test database, never live records.
3. Collect static files and verify CSS/JS and admin assets over HTTPS.
4. Run migrations on the separate hosted database, `python manage.py seed_roles`,
   then `python manage.py createsuperuser` securely in the service shell.
5. Using synthetic accounts, verify registration, email correction/recovery,
   reset OTP, cooldown, expiry, attempt lockout, and single use; verify actual
   inbox delivery and provider failures without sharing OTPs in screenshots/logs.
6. On the exact domain, register/authenticate passkeys and verify expired/replayed
   challenges fail. Confirm CSRF failures, HTTPS redirects, and secure cookies.
7. Verify voter/admin boundaries, one vote per election, result publication, and
   reports with synthetic elections. Check service logs for personal data.

Gunicorn access logs are disabled to avoid query-string/identifier disclosure.
Production Django request/security exception logs are suppressed because reports
can contain personal records; safe OTP provider-type diagnostics remain available.
Use Render status/health metrics for incident detection. Do not enable DEBUG or
third-party request-body capture. Administrator audit records intentionally contain
account-related data and must remain access-controlled.

Local development still loads the ignored .env and uses its existing DB_* and
email backend settings. No production provider credentials are required locally.

References: [Render Django](https://render.com/docs/deploy-django),
[WhiteNoise Django](https://whitenoise.readthedocs.io/en/stable/django.html),
[Brevo transactional API](https://developers.brevo.com/docs/send-a-transactional-email),
[PyMySQL connection options](https://pymysql.readthedocs.io/en/latest/modules/connections.html).
