from . import utils
from sendgrid import SendGridAPIClient
from django.conf import settings
from rest_framework.serializers import ValidationError

def api_send_email(data):
    try:
        SendGridAPIClient(api_key=settings.SENDGRID_API_KEY).client.mail.send.post(request_body=data)
    except Exception as e:
        print(e)
        raise ValidationError({"email_unsuccessful": "Error when sending email."})
        

def get_email_template(context):
    data = {
        "personalizations": [
        {
            "to": [
                {
                    "email": context["to"],
                }
            ],
            "dynamic_template_data": {
                "first_name": context["first_name"],
                "url": context["url"],
            }
        }
        ],
        "from": {
            "email": context["from_email"],
            "name": context["from_name"],
        },
        "template_id": context["template_id"]
    }
    return data   

def send_verification_email(context):
    context = utils.format_verification_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_activation_email(context):
    context = utils.format_activation_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_recovery_verification_email(context):
    context = utils.format_recovery_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_password_reset_email(context):
    context = utils.format_password_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_email_update_email(context):
    context = utils.format_update_email_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_deactivation_email(context):
    context = utils.format_deactivation_email_data(context)
    data = get_email_template(context)
    api_send_email(data)

def send_account_deletion_email(context):
    context = utils.format_account_deletion_data(context)
    data = get_email_template(context)
    api_send_email(data)