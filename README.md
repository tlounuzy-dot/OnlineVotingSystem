# SecureVote

SecureVote is an academic online voting prototype built with Django and MySQL.
It demonstrates voter registration, email verification, device authentication,
election administration, vote submission and controlled publication of results.
Use it for demonstrations and testing with synthetic identities.

**Ballot secrecy is not implemented.** The database retains a voter's identity,
selected candidate and IP address alongside an encrypted candidate reference.
This prototype is not certified for real elections.

## Features

- Voter registration with unique email/ID checks and a minimum age of 18 based
  on the submitted date of birth.
- Email-only OTP activation, pending-email correction and password recovery.
- OTP expiry, resend cooldown, attempt limits, hashing and single-use verification.
- Platform passkey registration and authentication using WebAuthn.
- Separate voter and administrator workflows, including voter status management.
- Election scheduling, candidate approval and voting availability checks.
- Ballot selection, confirmation and receipt, with a database constraint enforcing
  one vote per voter per election.
- Aggregate results, administrator-controlled publication, CSV reports and audit logs.

## Architecture

The application uses server-rendered Django templates with CSS and JavaScript.
Django handles HTTP requests, sessions, permissions, forms and database access.

| Component | Implementation |
| --- | --- |
| Runtime and framework | Python 3.13 recommended; Django 6.0.9 |
| Database | MySQL through PyMySQL's MySQLdb-compatible adapter |
| Device authentication | WebAuthn 3.0.0 with server-side challenge, origin, RP and signature verification |
| Vote protection | Fernet authenticated encryption through `cryptography`; plaintext candidate relationships remain stored |
| Local email | Console output by default with DEBUG enabled, or explicitly configured SMTP/Brevo |
| Hosted email | Brevo transactional email API over HTTPS |
| Hosted application | Render Linux service, Gunicorn 26.1.0 and WhiteNoise static file serving |
| Hosted database | Aiven MySQL with CA certificate and hostname verification |

Application responsibilities:

- `accounts/`: users, voter profiles, eligibility, OTPs, passkeys and audit records.
- `elections/`: elections, candidates and administrator/voter dashboards.
- `voting/`: ballot workflow, encryption and duplicate-vote protection.
- `reports/`: aggregate results, publication visibility and CSV exports.
- `online_voting_system/`: Django settings, validated production configuration and entry points.
- `tests/`: deployment configuration and mocked Brevo integration tests.

The configured timezone is `Africa/Johannesburg`. Local development loads an
ignored `.env`; existing process environment values take precedence. Production
requires `DJANGO_ENV=production`, reads deployment environment variables and does
not load `.env`. Although base settings have a SQLite fallback, the documented
installation and deployment workflows use MySQL.

## Authentication

Voters register with an email address, password and identity details. Successful
email OTP verification activates the account and verifies its voter profile.
Passwords are hashed by Django; OTP values are stored as hashes.

An eligible voter must register a platform passkey and authenticate it before
accessing protected voter pages. Authentication is required again after logout
and login. The server checks the challenge, relying-party ID, origin, signature
and user verification. The device may use fingerprint, face recognition, a PIN
or another local method; SecureVote does not receive raw biometric data or the
authenticator's private key. Administrator login follows a separate role-based
workflow and does not require the voter passkey step.

Default OTP controls are a 300-second lifetime, five attempts and a 60-second
resend cooldown. Password recovery uses email OTP and does not remove passkeys
or bypass voter access checks. Email verification proves access to a mailbox;
it does not establish a person's legal identity or electoral eligibility.

## Local installation

Follow [LOCAL_SETUP.md](LOCAL_SETUP.md) for the complete Windows/PowerShell
procedure, including independent database creation, credentials and email setup.
You need Python 3.13, MySQL 8.4 recommended, and a browser/device supporting
platform WebAuthn authentication. Record the Git revision used for testing.

In a new working directory:

```powershell
git clone https://github.com/tlounuzy-dot/OnlineVotingSystem.git SecureVote-local
Set-Location .\SecureVote-local
git rev-parse HEAD
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

Create a new local MySQL database and dedicated user as described in the setup
guide. In the fresh clone, copy `.env.example` to `.env` only if `.env` does not
already exist. Configure `DJANGO_ENV=development`, `DB_*`, a generated
`DJANGO_SECRET_KEY` and an independently generated `VOTE_ENCRYPTION_KEY`.
Replace example values before starting; keep all secrets private.

Use `WEBAUTHN_RP_ID=localhost` and `WEBAUTHN_ORIGIN=http://localhost:8000`.
Configure your own SMTP credentials for inbox testing, or follow
[ISOLATED_OTP_TEST.md](ISOLATED_OTP_TEST.md) for isolated Brevo testing.
Console email prints OTPs locally and provides no inbox delivery evidence.

After confirming the database is your new isolated database:

```powershell
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py seed_roles
.\.venv\Scripts\python.exe manage.py createsuperuser
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

Open **http://localhost:8000/** consistently for passkey ceremonies. Use `/login/`
for application access and `/admin/` for Django administration. Create test voters
through the registration/verification flow. `seed_roles` creates roles, not voters
or elections. Keep the development server bound to loopback.

## Deployment

Follow [DEPLOYMENT.md](DEPLOYMENT.md) for the Render/Aiven/Brevo configuration,
required environment variables, release commands and verification checklist.

- Render runs Gunicorn behind its HTTPS proxy; WhiteNoise serves collected static files.
- Aiven supplies a separate MySQL database and dedicated account with verified TLS.
- Brevo requires a transactional API key and verified sender, configured privately.
- Production validates required settings and rejects DEBUG, invalid origins and
  disabled secure-cookie/HTTPS controls.
- Choose the final HTTPS hostname before enrolling hosted passkeys. Local and
  tunnel credentials do not transfer to another relying party.

Install requirements and collect static files during the build; apply migrations
once per release before opening access. Configure secrets through the hosting
provider rather than committing `.env`, keys or database exports. The deployment
guide describes the intended architecture; it is not proof of a live deployment.
The repository does not include an infrastructure provisioning manifest.

## Testing

Use [TESTING_CHECKLIST.md](TESTING_CHECKLIST.md) for registration, recovery,
passkeys, permissions, election lifecycle, voting and result publication checks.
Use fictional identities and inboxes you control. Never include OTPs, passwords,
session cookies or credential payloads in shared evidence.

For automated tests, first follow the isolated test-database privilege and
name-conflict checks in [LOCAL_SETUP.md](LOCAL_SETUP.md), then run:

```powershell
.\.venv\Scripts\python.exe manage.py test --parallel 1
```

The runner creates and deletes a separate test database. Never run against shared
or production data or authorize deletion of an existing database without inspection.
Record the revision, discovered test count, environment versions and actual results.
Mocked Brevo and configuration tests do not prove real inbox delivery, provider
availability, hosted TLS connectivity or browser authentication success.

## Known limitations

- Voter/candidate relationships and IP addresses remain readable to authorized
  database users. Encrypting an additional field does not provide an anonymous
  ballot or end-to-end verifiable election.
- Submitted IDs and dates of birth are not checked against an authoritative voter register.
- SMS and WhatsApp OTP delivery are not supported; legacy models/migrations do
  not imply active provider integration.
- Passkey availability depends on browser, operating system and authenticator
  support. The application cannot require a specific biometric modality.
- Provider acceptance does not guarantee email delivery. The Brevo backend does
  not automatically retry uncertain deliveries.
- Retain the Fernet key securely with backups; changing it makes earlier encrypted
  references unreadable. A key-rotation workflow is not documented.
- Hosted request/security exception logs are suppressed and Gunicorn access logs
  are disabled. Monitoring and incident diagnosis require an operational plan.
- Mobile tunnel launchers are development utilities; use the documented hosted
  service for group access rather than treating a development tunnel as deployment.

## Documentation and academic attribution

The setup, deployment and testing guides describe supported workflows and their
validation limits. The academic attribution and historical validation note in
[ISOLATED_OTP_TEST.md](ISOLATED_OTP_TEST.md#academic-attribution-and-historical-validation-note)
preserves the existing assistance disclosure. Retain any acknowledgements required
by institutional policy and report actual contributor responsibilities and validation.
