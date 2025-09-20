# mpgepmcusers/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import uuid


GENDER_CHOICES = [
    ('male', 'Male'),
    ('female', 'Female'),
    ('other', 'Other'),
]


class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150)
    middle_name = models.CharField(max_length=150, blank=True, null=True)
    last_name = models.CharField(max_length=150)
    dob = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    gender_other_text = models.CharField(max_length=150, blank=True, null=True)
    mobile = models.CharField(max_length=20, unique=True)
    is_verified = models.BooleanField(default=False)  # OTP verified for signup

    def full_with_initials(self):
        fi = (self.first_name[0] + '.') if self.first_name else ''
        mi = (self.middle_name[0] + '.') if self.middle_name else ''
        return f"{fi}{mi} {self.last_name}".strip()


class OTP(models.Model):  # used for signup verification
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='otps')
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.PositiveSmallIntegerField(default=0)
    is_active = models.BooleanField(default=True)

    def expired(self):
        return timezone.now() > (self.created_at + timezone.timedelta(minutes=30))

    def mark_invalid(self):
        self.is_active = False
        self.save()


class PasswordResetToken(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="reset_tokens")
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def expired(self):
        # valid for 1 hour
        return timezone.now() > (self.created_at + timezone.timedelta(hours=1))
