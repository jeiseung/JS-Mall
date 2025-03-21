from accounts.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.utils import timezone

from firebase_admin import auth as firebase_auth

from accounts.accounts_repository import AccountsRepository
# from accounts.serializers import RegistrationSerializer


class AccountsService:
    @staticmethod
    def verify_firebase_id_token(token):
        try:
            return firebase_auth.verify_id_token(token)
        except firebase_auth.InvalidIdTokenError:
            return None

    @staticmethod
    def signin_user(token):
        decoded_token = AccountsService.verify_firebase_id_token(token)
        if not decoded_token:
            return {"error": "Invalid token"}, status.HTTP_401_UNAUTHORIZED
        uid = decoded_token['uid']
        user = AccountsRepository.check_user_exists_by_firebase_uid(uid)
        

        if user:
            if not user.is_active:
                return {"error": "Account is deactivated or has been terminated"}, status.HTTP_403_FORBIDDEN
            is_new_user = False
        else:
            email = decoded_token.get('email')
            username = decoded_token.get('name')

            user = User.objects.create(firebase_uid=uid, email=email, username=username)
            user.set_unusable_password() 
            user.is_email_verified = True
            user.email_verification_code = None  
            user.save()
            is_new_user = True

        last_login_before_update = user.last_login
        user.last_login = timezone.now()
        user.save()
        refresh = RefreshToken.for_user(user)
        return {
            "email": user.email,
            'user_name': user.username, 
            'last_login': last_login_before_update,
            'isNewUser': is_new_user,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status.HTTP_200_OK

   