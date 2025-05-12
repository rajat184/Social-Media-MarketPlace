from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

class FlexibleAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        try:
            # Try username first
            user = UserModel.objects.get(username=username)
            if user.check_password(password):
                return user
        except UserModel.DoesNotExist:
            # Try email as fallback
            try:
                user = UserModel.objects.get(email=username)
                if user.check_password(password):
                    return user
            except UserModel.DoesNotExist:
                return None
        return None