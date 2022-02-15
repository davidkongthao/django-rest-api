from .serializers import *
from . import utils
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()

client = APIClient()

def create_user():
    user = User.objects.create_user(
        email="launchrhub@gmail.com", 
        first_name="John", 
        last_name="Doe", 
        password="superstrongpassword12345!@#$%^",
    )
    return user

def print_out(response: str):
    print(
"""----------------------------------------------------------------------
{}
----------------------------------------------------------------------""".format(response)
)

class UserFunctionsTestCase(APITestCase):

    def test_sign_up(self):
        """
        Test that a user can sign up
        """
        data = {
            "email": "launchrhub@gmail.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "superstrongpassword12345!@#$%^",
            "password_confirm": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/users/", data=data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(User.objects.get(email="launchrhub@gmail.com").email, "launchrhub@gmail.com")

    def test_duplicate_sign_up(self):
        """
        Test that a user cannot sign up with an email that already exists
        """
        self.user = create_user()
        self.user.save()

        data = {
            "email": "launchrhub@gmail.com",
            "first_name": "John",
            "last_name": "Doe",
            "password": "superstrongpassword12345!@#$%^",
            "password_confirm": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/users/", data=data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_activation(self):
        """
        Test that a user can activate their account
        """
        self.user = create_user()
        self.user.is_active = False
        self.user.save()
        uid = utils.encode_uid(self.user.pk)
        token = default_token_generator.make_token(self.user)

        data = {
            "uid": uid,
            "token": token
        }

        response = self.client.post("/api/v1/users/activation/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.get(email="launchrhub@gmail.com").is_active, True)
    
    def test_jwt_refresh(self):
        """
        Test that a user can refresh their JWT
        """
        self.user = create_user()
        data = {
            "email": self.user.email,
            "password": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/jwt/create/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        data = {
            "refresh": response.data["refresh"]
        }

        response = self.client.post("/api/v1/jwt/refresh/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_verification(self):
        """
        Test that a user can verify their account.
        """
        self.user = create_user()
        self.user.is_verified = False
        self.user.save()

        data = {
            "email": self.user.email,
            "password": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/jwt/create/", data=data)

        token = default_token_generator.make_token(self.user)
        uid = utils.encode_uid(self.user.pk)
        data = {
            "uid": uid,
            "token": token
        }

        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["access"])

        response = self.client.post("/api/v1/users/me/email/verify/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.get(email="launchrhub@gmail.com").is_verified, True)
    
    def test_update_phone_number(self):
        """
        Test that a user can update their phone number
        """
        self.user = create_user()
        data = {
            "email": self.user.email,
            "password": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/jwt/create/", data=data)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["access"])

        data = {
            "phone_number": "+16124181371"
        }

        response = self.client.post("/api/v1/users/me/phone/update/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.get(email="launchrhub@gmail.com").phone_number.raw_input, data["phone_number"])

    def test_name_change(self):
        """
        Test that a user can change their name
        """
        self.user = create_user()

        data = {
            "email": self.user.email,
            "password": "superstrongpassword12345!@#$%^"
        }

        response = self.client.post("/api/v1/jwt/create/", data=data)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + response.data["access"])

        data = {
            "first_name": "NewFirstName",
            "last_name": "NewLastName"
        }

        response = self.client.post("/api/v1/users/me/name/change/", data=data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(User.objects.get(email=self.user.email).first_name, data["first_name"].capitalize())
        self.assertEqual(User.objects.get(email=self.user.email).last_name, data["last_name"].capitalize())