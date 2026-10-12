"""One-time operator tool. No .env loading, migrations, or public entry point."""

import ast
import logging
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import tempfile


CONFIRMATION = "CREATE ONE DEMO ADMIN IN securevote_test"
DATABASE = "securevote_test"
DATABASE_USER = "securevote_app"


def require(condition):
    if not condition:
        raise RuntimeError("Provisioning safety check failed")


def database_settings(env, ca_path):
    host = env["SV_PROVISION_HOST"].strip()
    require(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.aivencloud\.com", host))
    require(bool(env["SV_PROVISION_DB_PASSWORD"]))
    return {
        "ENGINE": "django.db.backends.mysql", "NAME": DATABASE,
        "USER": DATABASE_USER, "PASSWORD": env["SV_PROVISION_DB_PASSWORD"],
        "HOST": host, "PORT": 25586, "CONN_MAX_AGE": 0,
        "OPTIONS": {
            "ssl_ca": str(ca_path), "ssl_verify_cert": True,
            "ssl_verify_identity": True, "charset": "utf8mb4",
            "connect_timeout": 10, "read_timeout": 30, "write_timeout": 30,
        },
    }


def verify_connection(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE(), CURRENT_USER()")
        database, account = cursor.fetchone()
        require(database == DATABASE and account.split("@", 1)[0] == DATABASE_USER)
        cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_cipher'")
        cipher = cursor.fetchone()
        cursor.execute("SHOW SESSION STATUS LIKE 'Ssl_version'")
        version = cursor.fetchone()
        require(cipher and cipher[1] and version and version[1] in ("TLSv1.2", "TLSv1.3"))
        cursor.execute(
            "SELECT TABLE_NAME, ENGINE FROM information_schema.tables "
            "WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN (%s, %s)",
            (DATABASE, "accounts_role", "accounts_user"),
        )
        require(dict(cursor.fetchall()) == {
            "accounts_role": "InnoDB", "accounts_user": "InnoDB",
        })


def verify_migrations(connection):
    from django.db.migrations.executor import MigrationExecutor

    executor = MigrationExecutor(connection)
    executor.loader.check_consistent_history(connection)
    require(not executor.migration_plan(executor.loader.graph.leaf_nodes()))
    # Also refuse a checkout older than the hosted schema (unknown migrations).
    applied = set(executor.loader.applied_migrations)
    known = set(executor.loader.disk_migrations)
    require(applied <= known)


def create_admin(connection, email, password):
    from django.contrib.auth import get_user_model, password_validation
    from django.db import transaction
    from django.db.models import Q
    from accounts.models import Role

    User = get_user_model()
    email = email.strip().lower()
    require(bool(email) and bool(password))
    with transaction.atomic():
        # Serializes copies of this tool, without modifying the role row.
        role = Role.objects.select_for_update().get(name="Admin")
        require(not User.objects.filter(
            Q(role=role) | Q(is_staff=True) | Q(is_superuser=True)
        ).exists())
        require(not User.objects.filter(email__iexact=email).exists())
        fields = dict(email=email, full_name="SecureVote Demo Administrator",
                      role=role, status="active", is_active=True,
                      is_staff=True, is_superuser=False)
        candidate = User(**fields)
        password_validation.validate_password(password, candidate)
        candidate.full_clean(exclude=["password"])
        # Recheck the same connection immediately before the only INSERT.
        verify_connection(connection)
        created = User.objects.create_user(password=password, **fields)
        require(created.check_password(password) and created.is_staff
                and created.is_active and not created.is_superuser
                and created.status == "active" and created.role_id == role.pk)


def configure_django(project, database):
    import django
    from django.conf import settings

    require(django.get_version() == "6.0.9")
    # Parse literals only: importing project settings would load local .env.
    tree = ast.parse((project / "online_voting_system/settings.py").read_text(encoding="utf-8"))
    wanted = {"INSTALLED_APPS", "AUTH_USER_MODEL", "AUTH_PASSWORD_VALIDATORS"}
    definitions = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    definitions[target.id] = ast.literal_eval(node.value)
    require(definitions.keys() == wanted and definitions["AUTH_USER_MODEL"] == "accounts.User")
    require(bool(definitions["AUTH_PASSWORD_VALIDATORS"]))
    settings.configure(
        **definitions, DATABASES={"default": database},
        # Command-only random value; does not replace or need the hosted site key.
        SECRET_KEY=secrets.token_urlsafe(64), DEBUG=False, USE_TZ=True,
        TIME_ZONE="Africa/Johannesburg", LOGGING_CONFIG=None,
    )
    sys.path.insert(0, str(project))
    import pymysql

    pymysql.install_as_MySQLdb()
    django.setup()


def run():
    logging.disable(logging.CRITICAL)
    stage = "workflow authorization and deployed checkout"
    configured = False
    try:
        require(os.environ.get("GITHUB_ACTIONS") == "true")
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
        require(os.environ.get("GITHUB_REF") == "refs/heads/main")
        require(os.environ.get("RUNNER_OS") == "Linux" and sys.version_info[:2] == (3, 13))
        require(os.environ.get("SV_PROVISION_CONFIRMATION") == CONFIRMATION)
        expected = os.environ["SV_PROVISION_EXPECTED_SHA"]
        require(re.fullmatch(r"[0-9a-f]{40}", expected))
        actual = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL,
        ).strip()
        require(actual == expected)
        stage = "CA certificate and standalone configuration"
        with tempfile.TemporaryDirectory(prefix="securevote-admin-") as directory:
            ca = Path(directory) / "aiven-ca.pem"
            # Private file even if the runner's umask is permissive.
            with os.fdopen(os.open(ca, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
                handle.write(os.environ["SV_PROVISION_CA_PEM"])
            ssl.create_default_context(cafile=str(ca))
            configure_django(Path.cwd(), database_settings(os.environ, ca))
            configured = True
            from django.db import connection, connections

            try:
                stage = "TLS and database identity verification"
                verify_connection(connection)
                print("Verified securevote_test / securevote_app and validated TLS.")
                stage = "migration verification"
                verify_migrations(connection)
                stage = "Admin role, existing accounts, password validation and transaction"
                create_admin(connection, os.environ["SV_PROVISION_EMAIL"],
                             os.environ["SV_PROVISION_PASSWORD"])
                print("Created one active application administrator; superuser privileges are disabled.")
            finally:
                connections.close_all()
        return 0
    except Exception:
        # Never include exception text/tracebacks: providers may echo credentials,
        # SQL parameters, addresses or password-validator input.
        print("Provisioning stopped during " + stage + ". No sensitive error details logged. "
              "Do not blindly retry: a lost connection during commit can leave the account created. "
              "Verify account access privately before retrying.", file=sys.stderr)
        return 1
    finally:
        if configured:
            from django.db import connections
            try:
                connections.close_all()
            except Exception:
                pass
        for name in tuple(os.environ):
            if name.startswith("SV_PROVISION_"):
                os.environ.pop(name, None)


if __name__ == "__main__":
    sys.exit(run())
