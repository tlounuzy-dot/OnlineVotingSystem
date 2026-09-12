import accounts.fields
import base64
from django.db import migrations


def decode_existing_credential_ids(apps, schema_editor):
    WebAuthnCredential = apps.get_model("accounts", "WebAuthnCredential")
    for credential in WebAuthnCredential.objects.iterator():
        encoded_id = bytes(credential.credential_id).decode("ascii")
        credential.credential_id = base64.urlsafe_b64decode(
            encoded_id + "=" * (-len(encoded_id) % 4)
        )
        credential.save(update_fields=["credential_id"])


def encode_credential_ids_for_reverse(apps, schema_editor):
    WebAuthnCredential = apps.get_model("accounts", "WebAuthnCredential")
    for credential in WebAuthnCredential.objects.iterator():
        credential.credential_id = base64.urlsafe_b64encode(
            bytes(credential.credential_id)
        ).rstrip(b"=").decode("ascii")
        credential.save(update_fields=["credential_id"])


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0005_webauthnchallenge'),
    ]

    operations = [
        migrations.AlterField(
            model_name='webauthncredential',
            name='credential_id',
            field=accounts.fields.WebAuthnCredentialIDField(help_text='Opaque byte identifier from the authenticator.', max_length=1023, unique=True),
        ),
        migrations.RunPython(
            decode_existing_credential_ids,
            encode_credential_ids_for_reverse,
        ),
    ]
