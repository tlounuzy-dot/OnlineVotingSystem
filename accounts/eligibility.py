"""Server-side voter age eligibility rules."""

from datetime import date

from django.core.exceptions import ValidationError


MINIMUM_VOTING_AGE = 18


def calculate_age(date_of_birth: date, *, today: date | None = None) -> int:
    """Calculate full years, accounting for whether this year's birthday occurred."""
    today = today or date.today()
    return today.year - date_of_birth.year - (
        (today.month, today.day) < (date_of_birth.month, date_of_birth.day)
    )


def validate_voter_age(date_of_birth: date, *, today: date | None = None) -> None:
    """Raise a field-safe validation error for future or under-age birth dates."""
    today = today or date.today()
    if date_of_birth >= today:
        raise ValidationError("Date of birth must be in the past.", code="future_date")
    if calculate_age(date_of_birth, today=today) < MINIMUM_VOTING_AGE:
        raise ValidationError(
            "You must be at least 18 years old to register as a voter on SecureVote.",
            code="underage",
        )
