from django.contrib.auth.backends import BaseBackend
from .models import User
from django.contrib.auth.hashers import check_password
from django.http import HttpResponse


class MongoEngineBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None):
        try:
            user = User.objects.get(email=email)
            if check_password(password, user.password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None