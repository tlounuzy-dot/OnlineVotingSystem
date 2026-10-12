# SecureVote groupmate manual testing

Use LOCAL_SETUP.md and synthetic identities only. Each tester owns an independent
database and SMTP account. Use controlled email inboxes/aliases, fictional names
and IDs such as TEST-A-001, DOB 2000-01-01, and omit optional contact/address fields.
Do not use national IDs, real voter records, owner credentials or shared databases.

Record: tester label, date/time (with timezone), Git hash, Python/MySQL/browser/OS
versions, installed dependency versions, email provider name (no credentials),
and passkey method (Windows Hello PIN/fingerprint). Use Pass / Fail / Blocked /
Not tested, with expected versus actual behavior and reproduction steps.

Capture cropped UI screenshots and sanitized error/status messages. Hide inbox
addresses where practical. Never capture passwords, OTP digits, .env contents,
request bodies, cookies/session IDs, credential payloads or database dumps.
Record code delivery time and subject without showing the code. Clear passwords
from screenshots. A browser/authenticator limitation is Blocked, not Pass.

## Setup and roles

- [ ] Exact application revision identified; no unexpected local code edits.
- [ ] venv installation and pip check succeed; versions recorded.
- [ ] New MySQL database/user created independently; .env is ignored by Git.
- [ ] Django check passes; migration consistency reports no changes; migrations
  all applied on the separate test database. Capture sanitized command summary.
- [ ] seed_roles succeeds twice (second call reports already exists).
- [ ] Administrator created interactively; `/login/` opens admin dashboard.
- [ ] Home, forms, CSS, password-visibility control and navigation render correctly.

## Registration and pending-email recovery

- [ ] With an anonymous session, register Synthetic Voter A, adult DOB, unique
  fictional ID and controlled inbox. Expected: pending verification, email only;
  no SMS/WhatsApp selection.
- [ ] Invalid/mismatched or weak passwords rejected; duplicate email/ID rejected.
- [ ] Under-18 and future DOB rejected without an eligible voter being created.
- [ ] Request OTP. Inbox receives email; masked destination shown. Record elapsed
  delivery time and whether junk filtering intervened, without showing digits.
- [ ] Immediate resend blocked; resend after 60 seconds succeeds. Previous code
  fails; latest valid code activates account and verifies voter exactly once.
- [ ] Wrong six-digit code rejected. After five wrong attempts the code cannot be
  used even if correct; request a new one through the normal flow.
- [ ] Leave a new code unused for more than 300 seconds. It expires; a new code
  is required. Use real elapsed time, not edited settings or database rows.
- [ ] For Synthetic Voter B, stay pending; after cooldown use Change email to a
  second controlled alias. Expected: same pending identity/ID retained, old code
  invalidated, new code delivered to corrected destination, activation succeeds.
- [ ] Correction to another account's email rejected. Repeated immediate
  correction respects cooldown. Completed registration cannot be corrected via
  the pending flow.
- [ ] Log out or abandon a pending flow, then log in with its email/password.
  Expected: pending verification resumes rather than creating a duplicate voter.
- [ ] Optional SMTP failure test: on your own private configuration only, temporarily
  use an unavailable SMTP port, restart, request a code, and restore it afterward.
  Expected: safe delivery error, account remains pending, retry possible; no
  credentials/OTP shown in the browser. Mark blocked if provider testing is unavailable.

## Login and password recovery

- [ ] Wrong password rejected; correct active voter login enters device-verification
  flow. Login alone does not permit voting.
- [ ] Pending account cannot reach voting before OTP verification.
- [ ] While authenticated, attempts to start another registration/reset identity
  workflow produce session-conflict handling (409), without replacing current user.
- [ ] Log out, request reset for a controlled active email, receive email-only OTP,
  verify and set a new strong password. Old password fails; new password works.
- [ ] Reset OTP obeys cooldown, 300-second expiry, five-attempt lockout and single
  use. Resend invalidates previous code; registration OTP cannot authorize reset.
- [ ] Unknown reset email shows a generic recovery flow, not account existence.
- [ ] Direct new-password URL without verified reset session cannot change password.

## Passkey authentication

- [ ] On exact http://localhost:8000, activated voter registers a fresh platform
  credential; complete Windows Hello user verification. Success appears in UI.
- [ ] Cancel registration/authentication; expected safe error and no voting access.
- [ ] Authenticate enrolled passkey; voter dashboard becomes accessible.
- [ ] Log out, log in again; passkey authentication is required for the new session.
- [ ] Direct dashboard/ballot access before passkey verification routes back to
  verification; pending/suspended/rejected users remain denied as appropriate.
- [ ] Optional: let a ceremony sit past five minutes, then complete it. Expired
  challenge rejected; start a fresh ceremony. Automated tests cover replay/signature
  rejection; do not capture credential request payloads for manual evidence.

## Elections, voting and administrator boundaries

- [ ] In a separate browser profile for the admin, create a synthetic election
  with start before now and end later; use the configured Africa/Johannesburg time.
  Create at least two fictional candidates and approve them; activate election.
- [ ] Verified/passkey-authenticated voter sees eligible active election and
  approved candidates. Draft/closed elections do not allow vote submission.
- [ ] Choose candidate, review confirmation, submit once. Expected: success receipt;
  account cannot submit a second vote for that election, including refresh/back.
- [ ] Second synthetic voter can vote independently. Report aggregate results
  only; do not inspect/share voter-to-candidate database records.
- [ ] Admin candidate deactivation/election closure prevents later submissions
  even when a voter previously opened a ballot/confirmation page.
- [ ] Voter cannot open `/admin/dashboard/`, voter management, reports, audit or
  result-publication actions; denied access, no administrator data exposed.
- [ ] Admin can view voter status and authorized audit/report pages. Suspending
  a synthetic voter prevents continued access; no OTP reactivates a suspension.
- [ ] Close synthetic election and publish results. Voters see no unpublished
  results, then see correct aggregate totals after publication/refresh. Repeated
  publication does not duplicate the result or publication action.
- [ ] Administrator CSV/report contains expected synthetic aggregates and no
  encrypted-choice field. Capture summary rows only.

## Finish and report

- [ ] Optional MySQL serial tests executed only with dedicated test-database
  privileges; record count, duration and failures. Do not delete an existing test DB.
- [ ] Ctrl+C stops loopback server. Keep local test data/private .env on your machine;
  do not commit it or share logs containing console email/OTP output.
- [ ] Report each failed/blocked step with revision, versions, sanitized steps,
  expected/actual result and cropped evidence. Separate SMTP/browser prerequisites
  from application defects. Identify untested items explicitly.

The existing prototype retains voter/candidate relationships and IP addresses
beside encrypted choices. It is suitable for controlled synthetic group testing;
this checklist is not a secret-ballot security certification.
