# login/models.py
from django.db import models
from django.utils import timezone
from datetime import timedelta

class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + timedelta(minutes=5)  # 5-minute expiry

    def __str__(self):
        return f"{self.email} - {self.code} at {self.created_at}"


class PendingUser(models.Model):
    """
    Temporary storage for signup info until OTP is verified.
    """
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    password_hash = models.CharField(max_length=128)  # store hashed password
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PendingUser({self.email})"
