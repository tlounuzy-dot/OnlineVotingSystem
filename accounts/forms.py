from django import forms
from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError
from django.db import transaction

from .models import Role, User, Voter


class VoterRegistrationForm(forms.Form):
    full_name = forms.CharField(max_length=100)
    email = forms.EmailField()
    id_number = forms.CharField(max_length=20, label="ID number")
    date_of_birth = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    gender = forms.CharField(max_length=10, required=False)
    phone = forms.CharField(max_length=20, required=False)
    address = forms.CharField(max_length=255, required=False, widget=forms.Textarea(attrs={"rows": 3}))
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirmation = forms.CharField(label="Confirm password", widget=forms.PasswordInput)

    def clean_email(self):
        email = self.cleaned_data["email"].lower()
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("An account with this email address already exists.")
        return email

    def clean_id_number(self):
        id_number = self.cleaned_data["id_number"].strip()
        if Voter.objects.filter(id_number=id_number).exists():
            raise ValidationError("A voter with this ID number already exists.")
        return id_number

    def clean_date_of_birth(self):
        date_of_birth = self.cleaned_data["date_of_birth"]
        voter = Voter(date_of_birth=date_of_birth)
        try:
            voter.clean()
        except ValidationError as error:
            raise ValidationError(error.message_dict["date_of_birth"])
        return date_of_birth

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password_confirmation = cleaned_data.get("password_confirmation")

        if password and password_confirmation and password != password_confirmation:
            self.add_error("password_confirmation", "Passwords do not match.")

        if password:
            prospective_user = User(
                email=cleaned_data.get("email", ""),
                full_name=cleaned_data.get("full_name", ""),
            )
            try:
                password_validation.validate_password(password, prospective_user)
            except ValidationError as error:
                self.add_error("password", error)

        if not Role.objects.filter(name="Voter").exists():
            raise ValidationError("Registration is unavailable until the Voter role is initialized.")

        return cleaned_data

    def save(self):
        """Create the user and voter profile as a single database transaction."""
        if not self.is_valid():
            raise ValueError("Cannot save an invalid registration form.")

        with transaction.atomic():
            voter_role = Role.objects.get(name="Voter")
            user = User.objects.create_user(
                email=self.cleaned_data["email"],
                password=self.cleaned_data["password"],
                full_name=self.cleaned_data["full_name"],
                role=voter_role,
                status=User.Status.PENDING,
            )
            voter = Voter(
                user=user,
                id_number=self.cleaned_data["id_number"],
                date_of_birth=self.cleaned_data["date_of_birth"],
                gender=self.cleaned_data["gender"],
                phone=self.cleaned_data["phone"],
                address=self.cleaned_data["address"],
                status=Voter.Status.PENDING,
            )
            voter.full_clean()
            voter.save()

        return user


class EmailLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
