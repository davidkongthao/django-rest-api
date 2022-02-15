from django.contrib import admin
from .models import User

class UserAdmin(admin.ModelAdmin):
    list_display = tuple(User.REQUIRED_FIELDS) + tuple(User.PRIVATE_FIELDS)
    search_fields = tuple(User.SEARCH_FIELDS)

admin.site.register(User, UserAdmin)
