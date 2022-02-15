from . import (
        choices,
        locations
)
from organizations.models import Organization
from django.db import models, IntegrityError
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
import uuid

User = get_user_model()

class Domain(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    subscription_id = models.CharField(max_length=64)
    domain_name = models.CharField(max_length=256, unique=True, editable=False)
    contact_information = models.JSONField(default=dict)
    purchase_date = models.DateField(auto_now_add=True)
    expiration_date = models.DateField()
    privacy_enabled = models.BooleanField(default=True)
    is_billed_annually = models.BooleanField(default=True)
    auto_renew_enabled = models.BooleanField(default=True)

    REQUIRED_FIELDS = [
        "organization",
        "domain_name"
    ]
    
    class Meta:
        db_table = "services_domains"
        verbose_name = _("Domain")
        verbose_name_plural = _("Domains")

    def __str__(self):
        return self.domain_name
    
    def __self__(self):
        return self.domain_name

class BusinessOwnerAddress(models.Model):
    line1  = models.CharField(max_length=256)
    line2 = models.CharField(max_length=256, blank=True)
    city = models.CharField(max_length=256)
    state = models.CharField(max_length=128)
    country = models.CharField(max_length=128)
    postal_code = models.CharField(max_length=32)

    class Meta:
        db_table = "services_business_registration__owner__address"

class BusinessOwner(models.Model):
    first_name = models.CharField(max_length=256)
    middle_name = models.CharField(max_length=256, blank=True)
    last_name = models.CharField(max_length=256)
    email = models.EmailField(max_length=256, blank=True)
    phone = PhoneNumberField(blank=True, null=True)
    address = models.ForeignKey(BusinessOwnerAddress, on_delete=models.RESTRICT, null=True, blank=True)

    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
        "email"
    ]

class BusinessRegistration(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    subscription_id = models.CharField(max_length=64)
    business_name = models.CharField(max_length=256)
    business_delegation = models.CharField(max_length=128, choices=choices.BUSINESS_DELEGATIONS)
    state_of_registration = models.CharField(max_length=64, choices=locations.STATES)   
    outstanding_shares = models.IntegerField(default=0, null=True, blank=True)
    business_owners = models.JSONField(default=dict)
    business_addresses = models.JSONField(default=dict)
    incorporators = models.JSONField(default=dict)
    registered_agent = models.CharField(max_length=256)
    registered_agent_address = models.JSONField(default=dict)
    incorporation_document = models.FileField(upload_to="services/organizations/registrations/%Y/%m/%d/", blank=True)
    registration_date = models.DateField(auto_now_add=True)
    renewal_date = models.DateField()
   
    REQUIRED_FIELDS = [
        "registered_agent",
        "organization",
        "business_name",
        "state_of_registration",        
    ]

    NAME_FIELDS = [
        "first_name",
        "middle_name",
        "last_name",
        "suffix",
    ]

    ADDRESS_FIELDS = [
        "line1",
        "line2",
        "city",
        "state",
        "zip_code",
        "country",
    ]

    INCORPORATE_FIELDS = NAME_FIELDS + ADDRESS_FIELDS

    BUSINESS_OWNER_FIELDS = [
        "title",
        "shares_held",
        "percentage_of_shares",
    ] + NAME_FIELDS + ADDRESS_FIELDS

    class Meta:
        db_table = "services_business_registration"
        verbose_name = _("Business Registration")
        verbose_name_plural = _("Business Registrations")

    def __str__(self):
        return f"{self.business_name} {self.business_delegation} | {self.state_of_registration}"
    
    def __self__(self):
        return f"{self.business_name} {self.business_delegation} | {self.state_of_registration}"
