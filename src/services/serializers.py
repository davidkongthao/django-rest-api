from .models import (
    Domain, 
    BusinessRegistration
)
from organizations.models import Organization
from django.db import IntegrityError, transaction
from django.db.utils import IntegrityError
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.serializers import ValidationError
from django.conf import settings
from phonenumber_field.serializerfields import PhoneNumberField
from phonenumber_field.phonenumber import to_python
from PIL import Image
import stripe

stripe.api_key = settings.STRIPE_SECRET_KEY
stripe.max_network_retries = 2

User = get_user_model()

class DomainServiceSerializer(serializers.ModelField):

    class Meta:
        model = Domain
        fields = tuple(Domain.REQUIRED_FIELDS)
        