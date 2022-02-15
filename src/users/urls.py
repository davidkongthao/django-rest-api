from django.urls import path, include, re_path
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from . import views

router = DefaultRouter()
router.register("users", views.UserViewSet)

urlpatterns = [
    path("", include(router.urls)),
    re_path(r"^jwt/create/", views.CustomTokenObtainPairView.as_view(), name="jwt-create"),
    re_path(r"^jwt/2fa/create/", views.TwilioTokenVerifyView.as_view(), name="jwt-create-2fa"),
    re_path(r"^jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    re_path(r"^jwt/verify/", TokenVerifyView.as_view(), name="jwt-verify" ),
]