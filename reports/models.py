from django.core.exceptions import ValidationError
from django.db import models


class Result(models.Model):
    """Stored result snapshot for a candidate in an election."""

    election = models.ForeignKey("elections.Election", on_delete=models.CASCADE, related_name="results")
    candidate = models.ForeignKey("elections.Candidate", on_delete=models.CASCADE, related_name="results")
    total_votes = models.PositiveIntegerField(default=0)
    percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    generated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-total_votes", "candidate__full_name"]
        constraints = [
            models.UniqueConstraint(fields=["election", "candidate"], name="one_result_per_candidate_per_election"),
        ]

    def clean(self):
        if self.candidate_id and self.election_id and self.candidate.election_id != self.election_id:
            raise ValidationError("The candidate does not belong to this election.")

    def __str__(self):
        return f"{self.candidate.full_name}: {self.total_votes} votes"
