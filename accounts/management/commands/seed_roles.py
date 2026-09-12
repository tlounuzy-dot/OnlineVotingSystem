from django.core.management.base import BaseCommand

from accounts.models import Role


class Command(BaseCommand):
    help = "Create the required Admin and Voter roles when they do not exist."

    def handle(self, *args, **options):
        for name, description in (
            ("Admin", "System administration and election management."),
            ("Voter", "Registered voter access."),
        ):
            role, created = Role.objects.get_or_create(name=name, defaults={"description": description})
            outcome = "Created" if created else "Already exists"
            self.stdout.write(f"{outcome}: {role.name}")
