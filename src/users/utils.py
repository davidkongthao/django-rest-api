from . import constants
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.conf import settings
from twilio.rest import Client
from twilio.base import exceptions

EmailTemplate = constants.SendGrid.EmailTemplate
client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)

def validate_password_length(password):
    if len(password) > settings.PASSWORD_MAXIMUM_LENGTH:
        validation_error = "password_too_long"
        raise ValidationError({"password_too_long": "Password must not exceed {} characters.".format(settings.PASSWORD_MAXIMUM_LENGTH)}, code=validation_error)

def encode_uid(pk):
    return force_str(urlsafe_base64_encode(force_bytes(pk)))

def decode_uid(pk):
    return force_str(urlsafe_base64_decode(pk))

def get_user_email_field_name(user):
    return user.get_email_field_name()

def get_user_email(user):
    email_field_name = get_user_email_field_name(user)
    return getattr(user, email_field_name, None)

def has_digit(_string):
    contains_digit = any(map(str.isdigit, _string))
    return contains_digit

def send_sms_verification(phone_number):
    client.verify.services(settings.TWILIO_VERIFICATION_SERVICE_SID).verifications.create(to=phone_number, channel="sms")

def verify_sms_token(phone_number, code):
    try:
        verification_check = client.verify.services(settings.TWILIO_VERIFICATION_SERVICE_SID).verification_checks.create(to=phone_number, code=code)
        if verification_check.status == "approved":
            return True
        else:
            return False
    except exceptions.TwilioRestException:
        return False

def send_two_factor_auth_token(phone_number):
    try:
        verification = client.verify.services(settings.TWILIO_VERIFICATION_SERVICE_SID).verifications.create(to=phone_number, channel="sms")
        return verification
    except exceptions.TwilioRestException:
        return False

def cancel_stale_two_factor_auth_token(sid):
    data = client.verify.services(settings.TWILIO_VERIFICATION_SERVICE_SID).verifications(sid).update(status="canceled")
    return data

def get_protocol(request):
    protocol = "https:" if request.is_secure() else "http:"
    return protocol

def format_url_context(context):
    url = "{protocol}//{domain}/{function}/{token}/{uid}"

def format_data(user):
    data = {
        "first_name": user.first_name,
        "to": get_user_email(user),
        "from_email": settings.DEFAULT_FROM_EMAIL,
        "from_name": settings.DEFAULT_FROM_EMAIL_NAME
    }
    return data

def format_params(data):
    user = data["user"]

    params = {
        "protocol": get_protocol(data["request"]),
        "domain": settings.DOMAIN,
        "token": default_token_generator.make_token(user),
        "uid": encode_uid(user.pk),
    }

    return params

def format_verification_data(context):
    user = context["user"]
    params = format_params(context)
    params["function"] = "confirm-email"

    url = "{protocol}//{domain}/{function}/{uid}/{token}".format(**params)
    data = format_data(user)
    data["url"] = url
    data["template_id"] = EmailTemplate.VERIFICATION_TEMPLATE_ID

    return data

def format_activation_data(context):
    user = context["user"]
    params = format_params(context)
    params["function"] = "activation"
    url = "{protocol}//{domain}/{function}/{uid}/{token}".format(**params)
    data = format_data(user)
    data["url"] = url
    data["template_id"] = EmailTemplate.ACTIVATION_TEMPLATE_ID
    
    return data

def format_recovery_data(context):
    user = context["user"]
    params = format_params(context)
    params["function"] = "confirm-recovery-email"
    params["recovery_email"] = encode_uid(user.recovery_email)

    url = "{protocol}//{domain}/{function}/{uid}/{token}/{recovery_email}".format(**params)
    data = format_data(user)
    data["url"] = url
    data["to"] = user.recovery_email
    data["template_id"] = EmailTemplate.RECOVERY_EMAIL_VERIFICATION_TEMPLATE_ID

    return data

def format_password_data(context):
    user = context["user"]
    params = format_params(context)
    params["function"] = "reset-password"

    url = "{protocol}//{domain}/{function}/{uid}/{token}".format(**params)
    data = format_data(user)
    data["url"] = url
    data["template_id"] = EmailTemplate.PASSWORD_RESET_TEMPLATE_ID

    return data

def format_update_email_data(context):
    user = context["user"]
    params = format_params(context)
    params["function"] = "confirm-email-update"
    params["email"] = encode_uid(context["email"])

    url = "{protocol}//{domain}/{function}/{uid}/{token}/{email}".format(**params)
    data = format_data(user)
    data["url"] = url
    data["template_id"] = EmailTemplate.VERIFICATION_TEMPLATE_ID

    return data

def format_deactivation_email_data(context):
    user = context["user"] 
    url = None

    data = format_data(user)
    data["url"] = url
    data["template_id"] = constants.SendGrid.EmailTemplate.DEACTIVATION_TEMPLATE_ID

    return data

def format_account_deletion_data(context):
    user = context["user"]
    url = None

    data = format_data(user)
    data["url"] = url
    data["template_id"] = EmailTemplate.USER_DELETE_TEMPLATE_ID

    return data