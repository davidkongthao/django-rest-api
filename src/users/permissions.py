from rest_framework import permissions

class CurrentUserOrAdminOnly(permissions.IsAuthenticated):
    def has_object_permission(self, request, view, obj):
        user = request.user
        return user.is_admin or user.is_staff or obj.pk == user.pk
