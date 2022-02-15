from . import utils, messages, constants
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.contrib.auth.tokens import default_token_generator
from rest_framework import serializers, exceptions
from rest_framework.serializers import ValidationError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from phonenumber_field.serializerfields import PhoneNumberField
from phonenumber_field.phonenumber import to_python
import twilio

User = get_user_model()

class UserTokenSerializer(TokenObtainPairSerializer):
    token = serializers.CharField(min_length=6, required=True)

class UserFunctionsMixin:

    default_error_messages = {
        "inactive_account": messages.ErrorMessages.INACTIVE_ACCOUNT_ERROR,
        "user_does_not_exist": messages.ErrorMessages.USER_DOES_NOT_EXIST_ERROR,
    }

    def get_user(self):
        try:
            user = self.context["request"].user or self.user
            if not user.is_active:
                key_error = "inactive_account"
                raise ValidationError({"inactive_account": [self.error_messages[key_error]]}, code=key_error)
            return user
        except (User.DoesNotExist, KeyError, ValueError):
            key_error = "user_does_not_exist"
            raise ValidationError({"user_does_not_exist": [self.error_messages[key_error]]}, code=key_error)

class UserOrganizationSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = tuple(User.ORGANIZATION_FIELDS)
        read_only_fields = tuple(User.ORGANIZATION_FIELDS)

class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = tuple(User.PRIVATE_FIELDS)
        read_only_fields = tuple(User.READ_ONLY_FIELDS)
    
class AdminUserSerializer(UserSerializer):

    class Meta:
        model = User
        fields = UserSerializer.Meta.fields + tuple(User.ADMIN_FIELDS)
        read_only_fields = User.READ_ONLY_FIELDS 

class UserCreationSerializer(serializers.ModelSerializer):

    default_error_messages = {
        "cannot_create_user": messages.ErrorMessages.CANNOT_CREATE_USER_ERROR,
        "password_mismatch": messages.ErrorMessages.PASSWORD_MISMATCH_ERROR,
        "forbidden_character": messages.ErrorMessages.FORBIDDEN_CHARACTER_ERROR,
    }

    password = serializers.CharField(required=True, write_only=True, style={"input_type": "password"})
    password_confirm = serializers.CharField(required=True, write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        fields = tuple(User.REQUIRED_FIELDS) + (User.USERNAME_FIELD, "password", "password_confirm",)
    
    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            key_error = "password_mismatch"
            raise ValidationError({"password_mismatch": [self.error_messages[key_error]]}, code=key_error)
        
        first_name_digit = utils.has_digit(attrs["first_name"])
        last_name_digit = utils.has_digit(attrs["last_name"])

        if first_name_digit or last_name_digit:
            key_error = "forbidden_character"
            raise ValidationError({"forbidden_character": [self.error_messages[key_error]]}, code=key_error)

        return attrs

    def create(self, validated_data):
        try:
            user = self.perform_create(validated_data)
        except IntegrityError:
            self.fail("cannot_create_user")
        
        return user
    
    def perform_create(self, validated_data):
        with transaction.atomic():
            validated_data.pop("password_confirm")
            user = User(**validated_data)
            user.set_password(validated_data["password"])
            user.save()
        return user

class UidAndTokenSerializer(serializers.Serializer):
    
    default_error_messages = {
        "invalid_token": messages.ErrorMessages.INVALID_TOKEN_ERROR,
        "invalid_uid": messages.ErrorMessages.INVALID_UID_ERROR,
    }

    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        validated_data = super().validate(attrs)
        try:
            uid = utils.decode_uid(self.initial_data.get("uid", ""))
            self.user = User.objects.get(pk=uid)
        except (User.DoesNotExist, ValueError, TypeError, OverflowError):
            key_error = "invalid_uid"
            raise ValidationError({"invalid_uid": [self.error_messages[key_error]]}, code=key_error)
        
        is_token_valid = default_token_generator.check_token(self.user, self.initial_data.get("token", ""))

        if not is_token_valid:
            key_error = "invalid_token"
            raise ValidationError({"invalid_token": [self.error_messages[key_error]]}, code=key_error)
        
        return validated_data
    
    def get_user(self):
        return self.user

class ActivationSerializer(UidAndTokenSerializer):
    
    default_error_messages = {
        "stale_token": messages.ErrorMessages.STALE_TOKEN_ERROR,
    }

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if not self.user.is_active:
            return attrs
        raise exceptions.PermissionDenied(self.error_messages["stale_token"])
    
    def activate(self):
        user = self.user
        user.is_active = True
        if not user.is_verified:
            user.is_verified = True
        user.save()

class ResendVerifyEmailSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "email_already_verified": messages.ErrorMessages.EMAIL_ALREADY_VERIFIED_ERROR,
    }

    def validate(self, attrs):
        user = self.get_user()
        if user.is_verified:
            key_error = "email_already_verified"
            raise ValidationError({"email_already_verified": [self.error_messages[key_error]]}, code=key_error)
        return attrs

class TokenSerializer(serializers.Serializer):
    
    default_error_messages = {
        "invalid_token": messages.ErrorMessages.INVALID_TOKEN_ERROR,
    }

    token = serializers.CharField()

    def validate(self, attrs):
        user = self.get_user()
        validated_data = super().validate(attrs)
        is_token_valid = default_token_generator.check_token(user, self.initial_data.get("token", ""))
        if not is_token_valid:
            key_error = "invalid_token"
            raise ValidationError({"invalid_token": [self.error_messages[key_error]]}, code=key_error)
        return validated_data

class VerifyEmailSerializer(UidAndTokenSerializer, UserFunctionsMixin):
    
    def verify_email(self):
        user = self.get_user()
        if not user.is_verified:
            user.is_verified = True
            user.save()

class CurrentPasswordSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "current_password_incorrect": messages.ErrorMessages.PASSWORD_INCORRECT_ERROR,
    }

    current_password = serializers.CharField(required=True, style={"input_type": "password"})

    def validate(self, attrs):
        user = self.get_user()
        if not user.check_password(attrs["current_password"]):
            self.fail("current_password_incorrect")
        return attrs

class PasswordResetSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "password_mismatch": messages.ErrorMessages.PASSWORD_MISMATCH_ERROR,
    }

    new_password = serializers.CharField(required=True, style={"input_type": "password"})
    new_password_confirm = serializers.CharField(required=True, style={"input_type": "password"})

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            key_error = "password_mismatch"
            raise serializers.ValidationError({"password_mismatch": [self.error_messages[key_error]]}, code=key_error)
        return attrs

class ResendActivationEmailSerializer(serializers.Serializer):
    
    default_error_messages = {
        "account_active": messages.ErrorMessages.ACCOUNT_VERIFIED_ERROR,
        "account_not_found": messages.ErrorMessages.ACCOUNT_NOT_FOUND_ERROR,
    }

    email = serializers.EmailField(required=True)

    def validate_email(self, data):
        try:
            user = User.objects.get(email=data)
            if user.is_active:
                key_error = "account_active"
                raise ValidationError({"account_active": [self.error_messages[key_error]]}, code=key_error)
            return data
        except (User.DoesNotExist, KeyError, ValueError):
            key_error = "account_not_found"
            raise ValidationError({"account_not_found": [self.error_messages[key_error]]}, code=key_error)
    
    def get_user(self, validated_data):
        user = User.objects.get(email=validated_data["email"])
        return user

class EmailChangeSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "emails_not_matching": messages.ErrorMessages.EMAIL_NOT_MATCHING_ERROR,
        "no_changes_detected": messages.ErrorMessages.NO_CHANGES_DETECTED_ERROR,
        "email_recently_changed": messages.ErrorMessages.EMAIL_RECENTLY_CHANGED_ERROR,
    }

    email = serializers.EmailField(required=True)
    email_confirm = serializers.EmailField(required=True)

    def validate(self, attrs):
        user = self.get_user()
        last_modified = user.email_last_modified
        can_change_date = last_modified + timedelta(days=constants.DAYS_UNTIL_EMAIL_CHANGE_ALLOWED)

        if timezone.now() < can_change_date:
            remaining_days = (can_change_date - timezone.localtime())
            key_error = "email_recently_changed"
            raise ValidationError({"email_recently_changed": [self.error_messages[key_error].format(remaining_days.days)]}, code=key_error)

        if attrs["email"] != attrs["email_confirm"]:
            key_error = "emails_not_matching"
            raise ValidationError({"emails_not_matching": [self.error_messages[key_error]]}, code=key_error)
        elif attrs["email"] == user.email:
            key_error = "no_changes_detected"
            raise ValidationError({"no_changes_detected": [self.error_messages[key_error]]}, code=key_error)
        return attrs

class ConfirmEmailChangeSerializer(UidAndTokenSerializer, UserFunctionsMixin):

    default_error_messages = {
        "email_recently_changed": messages.ErrorMessages.EMAIL_RECENTLY_CHANGED_ERROR,
        "email_already_taken": messages.ErrorMessages.EMAIL_ALREADY_TAKEN_ERROR,
    }

    email = serializers.CharField()

    def update(self, instance, validated_data):
        user = self.get_user() or instance
        last_modified = user.email_last_modified
        can_change_date = last_modified + timedelta(days=constants.DAYS_UNTIL_EMAIL_CHANGE_ALLOWED)

        if timezone.now() < can_change_date:
            remaining_days = (can_change_date - timezone.localtime())
            key_error = "email_recently_changed"
            raise ValidationError({"email_recently_changed": [self.error_messages[key_error].format(remaining_days.days)]}, code=key_error)

        try:
            email = utils.decode_uid(validated_data["email"]).split("=")[1].split(" ")[0]
            user.email = email
            user.is_verified = False
            user.email_last_modified = timezone.now()
            user.save()
        except IntegrityError:
            key_error = "email_already_taken"
            raise ValidationError({"email_already_taken": [self.error_messages[key_error].format(validated_data["email"])]})
    

class UpdateRecoveryEmailSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "emails_not_matching": messages.ErrorMessages.EMAIL_NOT_MATCHING_ERROR,
        "email_matches_primary": messages.ErrorMessages.EMAIL_CANNOT_BE_PRIMARY_ERROR,
        "no_changes_detected": messages.ErrorMessages.NO_CHANGES_DETECTED_ERROR,
    }

    email = serializers.EmailField(required=True)
    email_confirm = serializers.EmailField(required=True)

    def validate(self, attrs):
        user = self.get_user()
        if attrs["email"] != attrs["email_confirm"]:
            key_error = "emails_not_matching"
            raise ValidationError({"emails_not_matching": [self.error_messages[key_error]]}, code=key_error)
        elif attrs["email"] == user.email:
            key_error = "email_matches_primary"
            raise ValidationError({"email_matches_primary": [self.error_messages[key_error]]}, code=key_error)
        elif attrs["email"] == user.recovery_email:
            key_error = "no_changes_detected"
            raise ValidationError({"no_changes_detected": [self.error_messages[key_error]]}, code=key_error)
        return attrs
    
    def update(self, instance, validated_data):
        user = self.get_user() or instance
        user.recovery_email = validated_data["email"]
        if user.recovery_email_verified == True:
            user.recovery_email_verified = False
        user.save()

class ResendRecoveryEmailVerificationSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "email_already_verified": messages.ErrorMessages.EMAIL_ALREADY_VERIFIED_ERROR,
        "no_recovery_email_set": messages.ErrorMessages.RECOVERY_EMAIL_NOT_SET_ERROR,
    }

    def validate(self, attrs):
        user = self.get_user()
        if user.recovery_email_verified:
            key_error = "email_already_verified"
            raise ValidationError({"email_already_verified": [self.error_messages[key_error]]}, code=key_error)
        if user.recovery_email == None:
            key_error = "no_recovery_email_set"
            raise ValidationError({"no_recovery_email_set": [self.error_messages[key_error]]}, code=key_error)
        return attrs

class VerifyRecoveryEmailSerializer(UidAndTokenSerializer, UserFunctionsMixin):
    
    default_error_messages = {
        "email_already_verified": messages.ErrorMessages.EMAIL_ALREADY_VERIFIED_ERROR,
        "invalid_recovery_email": messages.ErrorMessages.INVALID_RECOVERY_EMAIL_ERROR,
    }

    recovery_email = serializers.EmailField()

    def validate_recovery_email(self, value):
        user = self.get_user()
        recovery_email = utils.decode_uid(value)
        if user.recovery_email != recovery_email:
            key_error = "invalid_recovery_email"
            raise ValidationError({"invalid_recovery_email": [self.error_messages[key_error]]}, code=key_error)
        return value

    def verify_recovery_email(self):
        user = self.get_user()
        if user.recovery_email_verified != True:
            user.recovery_email_verified = True
            user.save()
        else:
            key_error = "email_already_verified"
            raise ValidationError({"email_already_verified": [self.error_messages[key_error]]}, code=key_error)

class ChangeNameSerializer(serializers.Serializer, UserFunctionsMixin):
    
    default_error_messages = {
        "forbidden_character": messages.ErrorMessages.FORBIDDEN_CHARACTER_ERROR,
    }

    first_name = serializers.CharField(required=False)
    last_name = serializers.CharField(required=False)

    def validate(self, attrs):
        first_name_digit = last_name_digit = None
        if "first_name" in attrs.keys():
            first_name_digit = utils.has_digit(attrs["first_name"])
        if "last_name" in attrs.keys():
            last_name_digit = utils.has_digit(attrs["last_name"])

        if (first_name_digit != None or last_name_digit != None) and (first_name_digit or last_name_digit):
            key_error = "forbidden_character"
            raise ValidationError({"forbidden_character": [self.error_messages[key_error]]}, code=key_error)

        return attrs
    
    def update(self, instance, validated_data):
        user = self.get_user() or instance
        state_changed = False
        if "first_name" in validated_data.keys():
            if user.first_name != validated_data["first_name"]:
                user.first_name = validated_data["first_name"].capitalize()
                state_changed = True
        if "last_name" in validated_data.keys():
            if user.last_name != validated_data["last_name"]:
                user.last_name = validated_data["last_name"].capitalize()
                state_changed = True
        if state_changed == True:
            user.save()

class SendPasswordEmailResetSerializer(serializers.Serializer):
    
    default_error_messages = {
        "account_not_found": messages.ErrorMessages.ACCOUNT_NOT_FOUND_ERROR,
    }

    email = serializers.EmailField(required=True)

    def validate_email(self, data):
        try:
            User.objects.get(email=data)
            return data
        except (User.DoesNotExist, KeyError, ValueError):
            key_error = "account_not_found"
            raise ValidationError({"account_not_found": [self.error_messages[key_error]]}, code=key_error)
    
    def get_user(self, validated_data):
        user = User.objects.get(email=validated_data["email"])
        return user

class UpdatePhoneNumberSerializer(UserFunctionsMixin, serializers.Serializer):
    
    default_error_messages = {
        "invalid_phone_number": messages.ErrorMessages.INVALID_PHONE_NUMBER_ERROR,
    }

    phone_number = PhoneNumberField()

    def update(self, instance, validated_data):
        user = self.get_user() or instance
        phone_number = to_python(validated_data["phone_number"])
        if phone_number and not phone_number.is_valid():
            key_error = "invalid_phone_number"
            raise ValidationError({"invalid_phone_number": [self.error_messages[key_error]]}, code=key_error)
        if user.phone_number != phone_number:
            user.phone_number = phone_number
            user.phone_number_verified = False
            user.save()
        utils.send_sms_verification(user.phone_number.raw_input)
        return instance, validated_data

class VerifyPhoneNumberSerializer(UserFunctionsMixin, serializers.Serializer):
    
    default_error_messages = {
        "invalid_code": messages.ErrorMessages.INVALID_PHONE_VERIFICATION_CODE_ERROR,
        "phone_number_verified": messages.ErrorMessages.PHONE_NUMBER_VERIFIED_ERROR,
    }

    code = serializers.CharField(max_length=6)

    def validate(self, attrs):
        user = self.get_user()
        try:
            phone_number = user.phone_number.raw_input
        except AttributeError:
            key_error = "invalid_code"
            raise ValidationError({"invalid_code": [self.error_messages[key_error]]}, code=key_error)
        try:
            is_valid_code = utils.verify_sms_token(phone_number, attrs["code"])
            if not is_valid_code:
                key_error = "invalid_code"
                raise ValidationError({"invalid_code": [self.error_messages[key_error]]}, code=key_error)
        except twilio.base.exceptions.TwilioRestException:
            if user.phone_number_verified:
                key_error = "phone_number_verified"
                raise ValidationError({"phone_number_verified": [self.error_messages[key_error]]}, code=key_error)
            utils.send_sms_verification(user.phone_number.raw_input)
        return attrs
    
    def update(self, instance):
        user = self.get_user() or instance
        user.phone_number_verified = True
        user.is_verified = True
        user.save()

class ResendPhoneNumberVerificationSerializer(UserFunctionsMixin, serializers.Serializer):
    
    default_error_messages = {
        "phone_number_verified": messages.ErrorMessages.PHONE_NUMBER_VERIFIED_ERROR,
        "no_phone_number": messages.ErrorMessages.NO_PHONE_NUMBER_ERROR,
    }

    def validate(self, attrs):
        user = self.get_user()
        if user.phone_number_verified:
            key_error = "phone_number_verified"
            raise ValidationError({"phone_number_verified": [self.error_messages[key_error]]}, code=key_error)
        return attrs
    
    def resend(self, instance):
        user = self.get_user() or instance
        if user.phone_number == None:
            key_error = "no_phone_number"
            raise ValidationError({"no_phone_number": [self.error_messages[key_error]]}, code=key_error)
        utils.send_sms_verification(user.phone_number.raw_input)

class UpdateTwoFactorAuthenticationSerializer(UserFunctionsMixin, serializers.Serializer):
    
    default_error_messages = {
        "no_changes_detected": messages.ErrorMessages.NO_CHANGES_DETECTED_ERROR,
        "no_phone_number": messages.ErrorMessages.NO_PHONE_NUMBER_ERROR,
        "phone_number_not_verified": messages.ErrorMessages.PHONE_NUMBER_UNVERIFIED_ERROR,
    }

    two_factor_sms_auth_enabled = serializers.BooleanField(required=True)

    def validate_two_factor_sms_auth_enabled(self, data):
        user = self.get_user()
        phone_check = user.phone_number != None
        if (
            phone_check and 
            data == True
        ):
            phone_number_verified = user.phone_number_verified
            if not phone_number_verified:
                key_error = "phone_number_not_verified"
                raise ValidationError({"phone_number_not_verified": [self.error_messages[key_error]]}, code=key_error)
        elif (
            not phone_check and 
            data == True
        ):
            key_error = "no_phone_number"
            raise ValidationError({"no_phone_number": [self.error_messages[key_error]]}, code=key_error)

        if user.two_factor_sms_auth_enabled == data:
            key_error = "no_changes_detected"
            raise ValidationError({"no_changes_detected": [self.error_messages[key_error]]}, code=key_error)

        return data

    def update(self, instance, validated_data):
        user = self.get_user() or instance
        user.two_factor_sms_auth_enabled = validated_data["two_factor_sms_auth_enabled"]
        user.save()

class PasswordChangeSerializer(CurrentPasswordSerializer, PasswordResetSerializer, UserFunctionsMixin):
    
    def change(self, instance, validated_data):
        user = self.get_user() or instance
        user.set_password(validated_data["new_password"])
        user.save()

class PasswordResetConfirmSerializer(UidAndTokenSerializer, PasswordResetSerializer):
    
    def reset(self, validated_data):
        self.user.set_password(validated_data["new_password"])
        self.user.save()
        return validated_data

class UserDeactivationSerializer(CurrentPasswordSerializer, UserFunctionsMixin):

    default_error_messages = {
        "cannot_deactivate": messages.ErrorMessages.CANNOT_DEACTIVATE_USER_ERROR,
    }

    confirm_deactivation = serializers.CharField()

    def validate_confirm_deactivation(self, data):
        if data != "CONFIRM":
            self.fail("cannot_deactivate")
        return data
    
    def deactivate(self, instance):
        user = self.get_user() or instance
        user.is_active = False
        user.save()

class UserDeleteSerializer(CurrentPasswordSerializer):
    
    default_error_messages = {
        "cannot_delete": messages.ErrorMessages.CANNOT_DELETE_USER_ERROR,
    }

    confirm_delete = serializers.CharField()

    def validate_confirm_delete(self, data):
        if data != r"DELETE":
            self.fail("cannot_delete")
        return data