from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    """Create users who sign in with their email address."""

    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("An email address is required.")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("status", "active")

        if extra_fields.get("is_staff") is not True:
            raise ValueError("A superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("A superuser must have is_superuser=True.")
        if extra_fields.get("is_active") is not True:
            raise ValueError("A superuser must have is_active=True.")

        # createsuperuser cannot safely supply a ForeignKey as a raw terminal
        # value. Resolve the stable application role here instead.
        role_model = self.model._meta.get_field("role").remote_field.model
        admin_role, _ = role_model.objects.get_or_create(
            name="Admin",
            defaults={"description": "System administration and election management."},
        )
        extra_fields["role"] = admin_role
        return self.create_user(email, password, **extra_fields)
