from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class Election(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        CLOSED = "closed", "Closed"
        CANCELLED = "cancelled", "Cancelled"

    title = models.CharField(max_length=150)
    description = models.CharField(max_length=255, blank=True)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="elections_created")
    created_at = models.DateTimeField(auto_now_add=True)
    results_published_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set only when final results are explicitly published after the election has closed.",
    )

    class Meta:
        ordering = ["-start_date"]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(end_date__gt=models.F("start_date")),
                name="election_end_date_after_start_date",
            ),
        ]

    def clean(self):
        if self.start_date and self.end_date and self.end_date <= self.start_date:
            raise ValidationError({"end_date": "End date must be after the start date."})

    @property
    def calculated_status(self):
        """Return the date-based status while preserving a manual cancellation."""
        if self.status == self.Status.CANCELLED:
            return self.Status.CANCELLED
        now = timezone.now()
        if now < self.start_date:
            return self.Status.PENDING
        if now >= self.end_date:
            return self.Status.CLOSED
        return self.Status.ACTIVE

    @property
    def is_open_for_voting(self):
        return self.status == self.Status.ACTIVE and self.calculated_status == self.Status.ACTIVE

    @property
    def results_are_published(self):
        return self.results_published_at is not None

    def __str__(self):
        return self.title


class Candidate(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        INACTIVE = "inactive", "Inactive"

    election = models.ForeignKey(Election, on_delete=models.CASCADE, related_name="candidates")
    full_name = models.CharField(max_length=100)
    party = models.CharField(max_length=100)
    manifesto = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.APPROVED)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["full_name"]

    def __str__(self):
        return f"{self.full_name} - {self.election.title}"

    @property
    def is_active(self):
        return self.status == self.Status.APPROVED
