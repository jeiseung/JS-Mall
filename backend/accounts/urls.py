from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, VerifyEmail ,ForgotPasswordAPI, GoogleSignInView , VerifyTokenView


router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

urlpatterns = [
    path('', include(router.urls)),
    path('signin/google/', GoogleSignInView.as_view(), name='google_signin'), 
    path('verify-email/', VerifyEmail.as_view(), name='verify_email_api'),
    path('forgot-password/', ForgotPasswordAPI.as_view(), name='forgot_password_api'),
    path('verify/token/', VerifyTokenView.as_view(), name='verify_token'),    
]
