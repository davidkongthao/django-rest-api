from . import utils
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from phonenumber_field.modelfields import PhoneNumberField
from django.utils.translation import gettext_lazy as _
import uuid

class UserManager(BaseUserManager):

    def create_user(self, email, first_name, last_name, password, **other_fields):

        if not email:
            raise ValueError("Email is required.")
        if not first_name:
            raise ValueError("First name is required.")
        if not last_name:
            raise ValueError("Last name is requried.")

        utils.validate_password_length(password)

        email = self.normalize_email(email)
        user = self.model(
            email = email,
            first_name = first_name,
            last_name = last_name,
        )

        user.set_password(password)
        user.save(self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password):

        utils.validate_password_length(password)

        email = self.normalize_email(email)
        user = self.model(
            email = email,
            first_name = first_name,
            last_name = last_name,
        )

        user.set_password(password)
        user.is_superuser = True
        user.is_admin = True
        user.is_staff = True
        user.save(self._db)
        return user


class User(AbstractUser):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    email = models.EmailField(max_length=128, unique=True)
    recovery_email = models.EmailField(max_length=128, unique=False, blank=True, null=True)
    first_name = models.CharField(max_length=64)
    last_name = models.CharField(max_length=64)
    phone_number = PhoneNumberField(blank=True, null=True)
    last_login = models.DateTimeField(auto_now=True)
    last_modified = models.DateTimeField(auto_now_add=True)
    email_last_modified = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    recovery_email_verified = models.BooleanField(default=False)
    phone_number_verified = models.BooleanField(default=False)
    notifications_enabled = models.BooleanField(default=False)
    two_factor_sms_auth_enabled = models.BooleanField(default=False)
    two_factor_sms_sent_at_time = models.DateTimeField(null=True, blank=True)
    two_factor_sms_sid = models.CharField(max_length=64, null=True, blank=True)

    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"

    ADMIN_FIELDS = [
        "is_superuser",
        "is_staff",
        "is_admin"
    ]

    REQUIRED_FIELDS = [
        "first_name",
        "last_name"
    ]

    PRIVATE_FIELDS = [
        "user_id",
        "email",
        "first_name",
        "last_name",
        "recovery_email",
        "phone_number",
        "last_login",
        "last_modified",
        "is_active",
        "recovery_email_verified",
        "phone_number_verified",
        "notifications_enabled",
        "two_factor_sms_auth_enabled"
    ]

    READ_ONLY_FIELDS = [
        "user_id",
        "last_login",
        "last_modified",
        "is_active",
        "is_verified",
        "recovery_email_verified",
        "phone_number_verified",
    ]
    
    ORGANIZATION_FIELDS = [
        "user_id",
        "email",
        "first_name",
        "last_name",
        "last_login",
        "is_active"
    ]
    
    SEARCH_FIELDS = [
        "email"
    ]

    class Meta:
        db_table = "users"
        ordering = ["email"]
    
    def __self__(self):
        return self.email

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        self.username = self.email
        super(User, self).save(*args, **kwargs)




