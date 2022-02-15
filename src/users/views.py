from .serializers import *
from .permissions import *
from . import utils, signals, email
from django.contrib.auth import get_user_model
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework.decorators import action
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = TokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        ret = super().post(request, *args, **kwargs)
        user = User.objects.get(username=request.data["email"])
        if user.two_factor_sms_auth_enabled:
            phone_number = user.phone_number.raw_input
            sms = utils.send_two_factor_auth_token(phone_number)
            if sms == False:
                return Response(
                    {"too_many_attempts": "Too many tokens have been sent. Please wait 10 minutes and try again."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            elif sms.status == "pending":
                last_four_digits = phone_number[-4:]
                return Response(
                    {"sms_token_sent": "SMS Token has been sent to the phone number ending in {}".format(last_four_digits)},
                    status=status.HTTP_206_PARTIAL_CONTENT
                )
            else:
                return Response(
                    {
                        "sms_token_error": sms["error_message"]
                    },
                    status=status.HTTP_503_SERVICE_UNAVAILABLE
                )
        return ret

class TwilioTokenVerifyView(TokenObtainPairView):
    serializer_class = UserTokenSerializer

    def post(self, request, *args, **kwargs):
        ret = super().post(request, *args, **kwargs)
        user = User.objects.get(username=request.data["email"])
        if user.two_factor_sms_auth_enabled:
            phone_number = user.phone_number.raw_input
            verification = utils.verify_sms_token(phone_number=phone_number, code=request.data["token"])
            if verification:
                return ret
            else:
                return Response(
                    {"sms_token_error": "Invalid token."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                {
                    "two_factor_error": "User not enabled for Two-Factor Authentication."
                },
                status=status.HTTP_400_BAD_REQUEST
            )

class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = User.objects.all()
    lookup_fields = User._meta.pk.name

    def permission_denied(self, request, **kwargs):
        user = request.user
        if (
            user.is_authenticated and
            (not user.is_admin or not user.is_staff) and
            self.action in ["list", "partial_update", "update", "retrive"]
        ):
            raise NotFound()
        super().permission_denied(request, **kwargs)
    
    def get_queryset(self):
        queryset = super().get_queryset()
        return queryset
    
    def get_permissions(self):
        if self.action in [
            "create", "activation", "resend_activation", "forgot_password",
            "forgot_password_confirm", "recover_account", "verify_email", "verify_recovery_email"
        ]:
            self.permission_classes = [permissions.AllowAny]
        elif self.action in [
            "update_phone_number", "update_email", "update_password", "change_name", 
            "destroy", "deactivate_account", "delete_account", "update", "resend_email_verification",
            "confirm_update_email", "resend_recovery_email_verification", "change_password",
            "update_two_factor_sms_auth_settings"
        ]:
            self.permission_classes = [CurrentUserOrAdminOnly]
        elif self.action == "list":
            self.permission_classes = [permissions.IsAdminUser]
        
        return super().get_permissions()
    
    def get_serializer_class(self):
        if self.action == "me":
            user = self.request.user
            if user.is_admin or user.is_staff or user.is_superuser:
                return AdminUserSerializer
            else:
                return UserSerializer
        elif self.action == "create":
            return UserCreationSerializer
        elif self.action == "change_name":
            return ChangeNameSerializer
        elif self.action == "activation":
            return ActivationSerializer
        elif self.action == "resend_email_verification":
            return ResendVerifyEmailSerializer
        elif self.action == "verify_email":
            return VerifyEmailSerializer
        elif self.action == "resend_activation":
            return ResendActivationEmailSerializer
        elif self.action == "forgot_password":
            return SendPasswordEmailResetSerializer
        elif self.action == "forgot_password_confirm":
            return PasswordResetConfirmSerializer
        elif self.action == "update_email":
            return EmailChangeSerializer
        elif self.action == "confirm_update_email":
            return ConfirmEmailChangeSerializer
        elif self.action == "change_password":
            return PasswordChangeSerializer
        elif self.action == "delete_account":
            return UserDeleteSerializer
        elif self.action == "update_phone_number":
            return UpdatePhoneNumberSerializer
        elif self.action == "verify_phone_number":
            return VerifyPhoneNumberSerializer
        elif self.action == "deactivate_account":
            return UserDeactivationSerializer
        elif self.action == "resend_phone_number_verification":
            return ResendPhoneNumberVerificationSerializer
        elif self.action == "update_recovery_email":
            return UpdateRecoveryEmailSerializer
        elif self.action == "resend_recovery_email_verification":
            return ResendRecoveryEmailVerificationSerializer
        elif self.action == "update_two_factor_sms_auth_settings":
            return UpdateTwoFactorAuthenticationSerializer
        elif self.action == "verify_recovery_email":
            return VerifyRecoveryEmailSerializer
        return self.serializer_class
    
    def get_instance(self):
        return self.request.user
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_instance()
        if instance == request.user:
            self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def perform_create(self, serializer):
        user = serializer.save()
        signals.user_registered.send(
            sender=self.__class__, 
            user=user, 
            request=self.request
        )
        context = {
            "user": user,
            "request": self.request,
            "action": self.action
        }
        email.send_verification_email(context)

    @action(["get"], detail=False)
    def me(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        if request.method == "GET":
            return self.retrieve(request, *args, **kwargs)
    
    @action(["post"], detail=False)
    def activation(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.activate()
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/name/change")
    def change_name(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance(), serializer.data)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="activation/resend")
    def resend_activation(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": serializer.get_user(serializer.data),
            "request": self.request,
            "action": self.action
        }
        email.send_activation_email(context)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/verify")
    def verify_email(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.verify_email()
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/recovery/verify")
    def verify_recovery_email(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.verify_recovery_email()
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/verify/resend")
    def resend_email_verification(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": serializer.get_user(),
            "request": self.request,
            "action": self.action
        }
        email.send_verification_email(context)
        return Response(status=status.HTTP_200_OK)

    @action(["post"], detail=False, url_path="me/email/recovery/verify/resend")
    def resend_recovery_email_verification(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": serializer.get_user(),
            "request": self.request,
            "action": self.action
        }
        email.send_recovery_verification_email(context)
        return Response(status=status.HTTP_200_OK)

    @action(["post"], detail=False, url_path="password/forgot")
    def forgot_password(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.get_user(validated_data=request.data)
        context = {
            "user": user,
            "request": self.request,
            "action": self.action
        }
        email.send_password_reset_email(context)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="password/forgot/confirm")
    def forgot_password_confirm(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.reset(serializer.data)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/update")
    def update_email(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": serializer.get_user(),
            "email": str(serializer["email"]),
            "request": self.request,
            "action": self.action
        }
        email.send_email_update_email(context)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/update/confirm")
    def confirm_update_email(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance(), serializer.data)
        context = {
            "user": serializer.get_user(),
            "request": self.request,
            "action": self.action
        }
        email.send_verification_email(context)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/email/recovery/update")
    def update_recovery_email(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance(), serializer.data)
        context = {
            "user": self.get_instance(),
            "request": self.request,
            "action": self.action
        }
        email.send_recovery_verification_email(context)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/password/change")
    def change_password(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.change(self.get_instance(), serializer.data)
        return Response(status=status.HTTP_200_OK)

    @action(["post"], detail=False, url_path="me/settings/security/2fa/sms/update")
    def update_two_factor_sms_auth_settings(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance(), serializer.data)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/phone/update")
    def update_phone_number(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance(), request.data)
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/phone/verify")
    def verify_phone_number(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(self.get_instance())
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/phone/verify/resend")
    def resend_phone_number_verification(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.resend(self.get_instance())
        return Response(status=status.HTTP_200_OK)
    
    @action(["post"], detail=False, url_path="me/deactivate")
    def deactivate_account(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": self.get_instance(),
            "request": self.request,
            "action": self.action
        }
        serializer.deactivate(self.get_instance())
        email.send_deactivation_email(context)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(["post"], detail=False, url_path="me/delete")
    def delete_account(self, request, *args, **kwargs):
        self.get_object = self.get_instance
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        context = {
            "user": self.get_instance(),
            "request": self.request,
            "action": self.action
        }
        email.send_account_deletion_email(context)
        return self.destroy(request, *args, **kwargs)