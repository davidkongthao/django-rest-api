from django.dispatch import Signal
from django.contrib.auth import get_user_model

User = get_user_model()

user_registered = Signal()