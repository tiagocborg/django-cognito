import requests
import json
import boto3
import jwt

from django.contrib.auth.base_user import BaseUserManager
from django.db import models, IntegrityError
from django.utils import timezone

from django.apps import apps as django_apps
from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from rest_framework import exceptions
from jwt.algorithms import RSAAlgorithm


class CognitoAuth(ModelBackend):
    POOL_URL = f"https://cognito-idp.{settings.COGNITO_AWS_REGION}.amazonaws.com/{settings.COGNITO_USER_POOL}"

    def authenticate(self, request, username=None, password=None, **kwargs):
        data = {
            "AuthParameters": {
                "USERNAME": f"{username}",
                "PASSWORD": f"{password}",
            },
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": settings.COGNITO_CLIENT_ID
        }

        client = boto3.client('cognito-idp', 'eu-west-1')

        try:
            result = client.initiate_auth(
                ClientId=data['ClientId'],
                AuthFlow=data['AuthFlow'],
                AuthParameters=data['AuthParameters']
            )
        except (TokenError, client.exceptions.NotAuthorizedException, client.exceptions.UserNotFoundException):
            raise exceptions.NotAuthenticated()

        jwt_payload = self._validate_token(result["AuthenticationResult"]["IdToken"])

        USER_MODEL = django_apps.get_model(settings.AUTH_USER_MODEL, require_ready=False)
        user = USER_MODEL.objects.get_or_create_for_cognito(jwt_payload)
        return user

    def _validate_token(self, token):
        public_key = self._get_public_key(token)
        if not public_key:
            raise TokenError("Key not found for the given token.")
        import pdb
        pdb.set_trace()
        try:
            jwt_data = jwt.decode(
                token,
                public_key,
                audience=settings.COGNITO_CLIENT_ID,
                issuer=self.POOL_URL,
                algorithms=["RS256"],
            )
        except (jwt.InvalidTokenError, jwt.ExpiredSignature, jwt.DecodeError) as exc:
            raise TokenError(str(exc))
        return jwt_data

    def _json_web_keys(self):
        response = requests.get(self.POOL_URL + "/.well-known/jwks.json")
        response.raise_for_status()
        data = response.json()
        return {item["kid"]: json.dumps(item) for item in data["keys"]}

    def _get_public_key(self, token):
        try:
            headers = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise TokenError(str(exc))
        jwk_data = self._json_web_keys().get(headers["kid"])
        return RSAAlgorithm.from_jwk(jwk_data)


class TokenError(Exception):
    pass


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)

        user = self.model(
            email=email,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and saves a superuser with the given email and password.

        :type email: String
        :param email: The email for the new user

        :type password: String
        :param password: The password for the new user

        :type extra_fields: dict
        :param extra_fields: A dict with additional information for the new user
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        return self._create_user(email, password, **extra_fields)

    def create_user(self, email=None, password=None, **extra_fields):
        """
        Create and saves an user with the given email and password.

        :type email: String
        :param email: The email for the new user

        :type password: String
        :param password: The password for the new user

        :type extra_fields: dict
        :param extra_fields: A dict with additional information for the new user
        """
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)

        return self._create_user(email, password, **extra_fields)

    def get_or_create_for_cognito(self, payload):
        groups = payload["cognito:groups"]
        cognito_id = payload['sub']

        try:
            return self.get(cognito_id=cognito_id)
        except self.model.DoesNotExist:
            pass

        try:
            user = self.create(
                cognito_id=cognito_id,
                email=payload['email'],
                is_active=True,
                is_superuser='Admin' in payload['cognito:groups']
            )
        except IntegrityError:
            user = self.get(cognito_id=cognito_id)

        user.given_name = payload['given_name']
        user.family_name = payload['family_name']
        user.company = payload['custom:company']

        if "Admin" in groups:
            user.is_superuser = True
            user.is_staff = True

        user.save()

        return user
