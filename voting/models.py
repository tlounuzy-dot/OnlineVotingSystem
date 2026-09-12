from django.core.exceptions import ValidationError
from django.db import models


class Vote(models.Model):
    class Status(models.TextChoices):
        VALID = "valid", "Valid"
        INVALID = "invalid", "Invalid"
        FLAGGED = "flagged", "Flagged"

    voter = models.ForeignKey("accounts.Voter", on_delete=models.PROTECT, related_name="votes")
    candidate = models.ForeignKey("elections.Candidate", on_delete=models.PROTECT, related_name="votes")
    election = models.ForeignKey("elections.Election", on_delete=models.PROTECT, related_name="votes")
    encrypted_choice = models.BinaryField(
        null=True,
        blank=True,
        editable=False,
        help_text="Application-encrypted candidate reference for this student-project prototype.",
    )
    voted_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.VALID)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ["-voted_at"]
        indexes = [models.Index(fields=["election", "status"])]
        constraints = [
            models.UniqueConstraint(fields=["voter", "election"], name="one_vote_per_voter_per_election"),
        ]

    def clean(self):
        if self.candidate_id and self.election_id and self.candidate.election_id != self.election_id:
            raise ValidationError("The selected candidate does not belong to this election.")

    def __str__(self):
        return f"Vote {self.pk or 'new'} for {self.election}"
