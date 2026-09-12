from django.db import models


class WebAuthnCredentialIDField(models.BinaryField):
    """A WebAuthn credential ID stored as its original opaque byte sequence."""

    description = "WebAuthn credential ID"

    def db_type(self, connection):
        # A unique BLOB index needs a prefix on MySQL, which would not enforce
        # uniqueness over the complete credential ID. VARBINARY(1023) indexes
        # the whole WebAuthn maximum-length credential ID instead.
        if connection.vendor == "mysql":
            return "varbinary(1023)"
        return super().db_type(connection)
