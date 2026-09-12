from django import forms
from django.core.exceptions import ValidationError
from .models import Candidate, Election


class ElectionForm(forms.ModelForm):
    class Meta:
        model = Election
        fields = ["title", "description", "start_date", "end_date"]
        widgets = {"start_date": forms.DateTimeInput(attrs={"type": "datetime-local"}), "end_date": forms.DateTimeInput(attrs={"type": "datetime-local"})}

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("start_date") and cleaned.get("end_date") and cleaned["end_date"] <= cleaned["start_date"]:
            self.add_error("end_date", "End date must be after the start date.")
        return cleaned


class CandidateForm(forms.ModelForm):
    class Meta:
        model = Candidate
        fields = ["election", "full_name", "party", "manifesto", "status"]

    def clean_election(self):
        election = self.cleaned_data["election"]
        if election.calculated_status in {Election.Status.CLOSED, Election.Status.CANCELLED}:
            raise ValidationError("Candidates cannot be changed for a closed or cancelled election.")
        return election
