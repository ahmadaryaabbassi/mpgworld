# mpgepmcusers/forms.py
from django import forms
from django.core.exceptions import ValidationError
from .validators import valid_password, valid_name, valid_email_domain, valid_mobile, valid_age
from .models import CustomUser


class SignupForm(forms.Form):
    first_name = forms.CharField(max_length=150)
    middle_name = forms.CharField(max_length=150, required=False)
    last_name = forms.CharField(max_length=150)
    dob = forms.DateField(widget=forms.DateInput(attrs={'type': 'date'}))
    gender = forms.ChoiceField(choices=[('male', 'Male'), ('female', 'Female'), ('other', 'Other')])
    gender_other_text = forms.CharField(required=False, max_length=150)
    mobile = forms.CharField(max_length=20)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean_first_name(self):
        v = self.cleaned_data['first_name']
        if not valid_name(v):
            raise ValidationError("Invalid first name format.")
        return v

    def clean_last_name(self):
        v = self.cleaned_data['last_name']
        if not valid_name(v):
            raise ValidationError("Invalid last name format.")
        return v

    def clean_email(self):
        email = self.cleaned_data['email']
        if not valid_email_domain(email):
            raise ValidationError("Email domain not allowed.")
        if CustomUser.objects.filter(email__iexact=email).exists():
            raise ValidationError("Email already in use.")
        return email.lower()

    def clean_mobile(self):
        m = self.cleaned_data['mobile']
        if not valid_mobile(m):
            raise ValidationError("Invalid mobile format.")
        if CustomUser.objects.filter(mobile=m).exists():
            raise ValidationError("Mobile already in use.")
        return m

    def clean_dob(self):
        dob = self.cleaned_data['dob']
        if not valid_age(dob):
            raise ValidationError("Age must be between 12 and 150.")
        return dob

    def clean(self):
        cleaned = super().clean()
        p, cp = cleaned.get('password'), cleaned.get('confirm_password')
        if p and cp and p != cp:
            self.add_error('confirm_password', "Passwords do not match.")
        if p:
            ok, msg = valid_password(p)
            if not ok:
                self.add_error('password', msg)
        if cleaned.get('gender') == 'other' and not cleaned.get('gender_other_text'):
            self.add_error('gender_other_text', "Please describe your gender if 'Other'.")
        return cleaned


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField()


class ResetPasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def clean_password(self):
        pw = self.cleaned_data.get("password")
        ok, msg = valid_password(pw)
        if not ok:
            raise ValidationError(msg)
        return pw

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned


class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput)
    new_password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_old_password(self):
        old_pw = self.cleaned_data.get("old_password")
        if not self.user.check_password(old_pw):
            raise ValidationError("Old password incorrect.")
        return old_pw

    def clean_new_password(self):
        new_pw = self.cleaned_data.get("new_password")
        ok, msg = valid_password(new_pw)
        if not ok:
            raise ValidationError(msg)
        if self.cleaned_data.get("old_password") and new_pw == self.cleaned_data["old_password"]:
            raise ValidationError("New password cannot equal old password.")
        return new_pw

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("new_password") != cleaned.get("confirm_password"):
            self.add_error("confirm_password", "Passwords do not match.")
        return cleaned
