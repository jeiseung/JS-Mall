from accounts.models import User
import firebase_admin
from django.conf import settings
from firebase_admin import credentials

default_app = None
if not firebase_admin._apps:
    service_account_key_path = settings.FIREBASE_SERVICE_ACCOUNT_KEY
    cred = credentials.Certificate(service_account_key_path)
    firebase_admin.initialize_app(cred)


class AccountsRepository:
    @staticmethod
    def check_user_exists_by_firebase_uid(uid):
        return User.objects.filter(firebase_uid=uid).first()

    @staticmethod
    def get_user_by_firebase_uid(uid):
        return User.objects.get(firebase_uid=uid)
