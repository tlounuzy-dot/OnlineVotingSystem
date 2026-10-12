"""Offline tests: a new in-memory SQLite database, never .env or MySQL."""

from contextlib import redirect_stderr
import io
import os
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

import provision_demo_admin as provision


class ConnectionChecks(unittest.TestCase):
    def connection(self, database="securevote_test", account="securevote_app@%",
                   cipher="TLS_AES_256_GCM_SHA384", version="TLSv1.3", engine="InnoDB"):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [(database, account), ("Ssl_cipher", cipher), ("Ssl_version", version)]
        cursor.fetchall.return_value = [("accounts_role", engine), ("accounts_user", engine)]
        return connection

    def test_valid_connection(self):
        provision.verify_connection(self.connection())

    def test_wrong_database(self):
        with self.assertRaises(RuntimeError):
            provision.verify_connection(self.connection(database="online_voting_db"))

    def test_wrong_database_account(self):
        with self.assertRaises(RuntimeError):
            provision.verify_connection(self.connection(account="root@%"))

    def test_unencrypted_connection(self):
        with self.assertRaises(RuntimeError):
            provision.verify_connection(self.connection(cipher=""))

    def test_old_tls(self):
        with self.assertRaises(RuntimeError):
            provision.verify_connection(self.connection(version="TLSv1"))

    def test_nontransactional_table(self):
        with self.assertRaises(RuntimeError):
            provision.verify_connection(self.connection(engine="MyISAM"))

    def test_settings_force_target_and_tls(self):
        values = provision.database_settings({"SV_PROVISION_HOST": "demo.aivencloud.com",
                                              "SV_PROVISION_DB_PASSWORD": "synthetic"}, Path("ca.pem"))
        self.assertEqual((values["NAME"], values["USER"], values["PORT"]),
                         ("securevote_test", "securevote_app", 25586))
        self.assertIs(values["OPTIONS"]["ssl_verify_cert"], True)
        self.assertIs(values["OPTIONS"]["ssl_verify_identity"], True)

    def test_non_aiven_host_rejected(self):
        with self.assertRaises(RuntimeError):
            provision.database_settings({"SV_PROVISION_HOST": "localhost",
                                         "SV_PROVISION_DB_PASSWORD": "synthetic"}, Path("ca.pem"))

    def test_missing_confirmation_fails_without_connection_and_clears_secrets(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false",
                                     "SV_PROVISION_PASSWORD": "synthetic-secret"}, clear=True):
            output = io.StringIO()
            with patch.object(provision, "configure_django") as configure, redirect_stderr(output):
                self.assertEqual(provision.run(), 1)
            configure.assert_not_called()
            self.assertNotIn("synthetic-secret", output.getvalue())
            self.assertNotIn("SV_PROVISION_PASSWORD", os.environ)


class AccountChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from django.conf import settings
        if settings.configured:
            raise RuntimeError("Run this test in a fresh process")
        provision.configure_django(Path(__file__).resolve().parents[1],
                                  {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"})
        from django.core.management import call_command
        from django.db import connection
        if connection.settings_dict["NAME"] != ":memory:":
            raise RuntimeError("Offline tests require in-memory storage")
        # Historical MySQL migration names this collation. Supply an equivalent
        # comparator only in this disposable SQLite fixture, never in the app.
        connection.ensure_connection()
        connection.connection.create_collation("ascii_bin", lambda a, b: (a > b) - (a < b))
        call_command("migrate", verbosity=0, interactive=False)

    def setUp(self):
        from accounts.models import Role, User
        from django.db import transaction
        self.User = User
        self.Role = Role
        self.atomic = transaction.atomic()
        self.atomic.__enter__()
        self.addCleanup(self.rollback)
        self.role = Role.objects.create(name="Admin")
        self.password = "Synthetic-Only!oG7uT42$zqN"

    def rollback(self):
        from django.db import transaction
        transaction.set_rollback(True)
        self.atomic.__exit__(None, None, None)

    def create(self, email="demo@example.invalid", password=None):
        from django.db import connection
        # Only MySQL/TLS metadata is mocked; manager, validators and transactions are real.
        with patch.object(provision, "verify_connection"):
            provision.create_admin(connection, email, self.password if password is None else password)

    def test_creates_exactly_one_staff_admin_with_hashed_password(self):
        self.create()
        user = self.User.objects.get()
        self.assertTrue(user.is_staff and user.is_active and user.check_password(self.password))
        self.assertFalse(user.is_superuser)
        self.assertEqual(user.status, "active")
        self.assertEqual(user.role_id, self.role.pk)
        self.assertNotEqual(user.password, self.password)
        from accounts.models import Voter
        self.assertEqual(Voter.objects.count(), 0)

    def test_repeat_refused(self):
        self.create()
        with self.assertRaises(RuntimeError):
            self.create(email="second@example.invalid")
        self.assertEqual(self.User.objects.count(), 1)

    def test_each_kind_of_existing_administrator_refused(self):
        voter_role = self.Role.objects.create(name="Voter")
        for flags in ({"role": self.role}, {"role": voter_role, "is_staff": True},
                      {"role": voter_role, "is_superuser": True}):
            with self.subTest(flags=list(flags)):
                existing = self.User.objects.create_user(email="existing@example.invalid", **flags)
                with self.assertRaises(RuntimeError):
                    self.create()
                self.assertEqual(self.User.objects.count(), 1)
                existing.delete()

    def test_duplicate_email_preserves_existing_user(self):
        role = self.Role.objects.create(name="Voter")
        existing = self.User.objects.create_user(email="demo@example.invalid", role=role, status="pending")
        with self.assertRaises(RuntimeError):
            self.create(email="DEMO@example.invalid")
        existing.refresh_from_db()
        self.assertEqual(existing.status, "pending")
        self.assertFalse(existing.is_staff)

    def test_weak_password_refused(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            self.create(password="123")
        self.assertEqual(self.User.objects.count(), 0)

    def test_invalid_email_refused(self):
        from django.core.exceptions import ValidationError
        with self.assertRaises(ValidationError):
            self.create(email="invalid")
        self.assertEqual(self.User.objects.count(), 0)

    def test_missing_admin_role_refused(self):
        self.role.delete()
        with self.assertRaises(self.Role.DoesNotExist):
            self.create()
        self.assertEqual(self.User.objects.count(), 0)

    def test_verification_failure_rolls_back_insert(self):
        with patch.object(self.User, "check_password", return_value=False):
            with self.assertRaises(RuntimeError):
                self.create()
        self.assertEqual(self.User.objects.count(), 0)

    def test_pending_and_unknown_migrations_refused(self):
        with patch("django.db.migrations.executor.MigrationExecutor") as executor:
            executor.return_value.migration_plan.return_value = [object()]
            with self.assertRaises(RuntimeError):
                provision.verify_migrations(MagicMock())
            executor.return_value.migration_plan.return_value = []
            executor.return_value.loader.applied_migrations = {("accounts", "unknown")}
            executor.return_value.loader.disk_migrations = {}
            with self.assertRaises(RuntimeError):
                provision.verify_migrations(MagicMock())


if __name__ == "__main__":
    unittest.main()
