from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .serializers import RegistrationSerializer, MyTokenObtainPairSerializer, UserSerializer,UpdateUsernameSerializer
from django.contrib.auth.models import update_last_login
from .models import User
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.utils import timezone
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from accounts.accounts_service import AccountsService


from rest_framework.views import APIView 
import uuid


import logging
import firebase_admin
from django.conf import settings
from firebase_admin import credentials

logger = logging.getLogger(__name__)

default_app = None
if not firebase_admin._apps:
    service_account_key_path = settings.FIREBASE_SERVICE_ACCOUNT_KEY
    cred = credentials.Certificate(service_account_key_path)
    firebase_admin.initialize_app(cred)

class UserViewSet(viewsets.GenericViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    @action(detail=False, methods=['put', 'patch'], permission_classes=[permissions.IsAuthenticated])
    def update_username(self, request):
        user = request.user
        serializer = UpdateUsernameSerializer(instance=user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"Username updated for user {user.email}")
            return Response({'detail': 'Username updated successfully.', 'user': UserSerializer(user).data}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated])
    def info(self, request):
        user = request.user
        serializer = self.get_serializer(user)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def signup(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            verification_url = f"{settings.HOST_URL}/accounts/verify-email/?code={user.email_verification_code}"
            subject = "[store.studyola.com] Verify your email address"
            message = f"Please click the link below to verify your email address:\n <link> {verification_url} </link>"
            
            html_message = f"""
                <html>
                <head>
                    <style>
                        .email-container {{
                            font-family: Arial, sans-serif;
                            line-height: 1.6;
                            color: #333;
                        }}
                        .email-header {{
                            background-color: #f4f4f4;
                            padding: 10px;
                            text-align: center;
                            font-size: 1.2em;
                            color: #333;
                        }}
                        .email-body {{
                            margin: 20px;
                            padding: 20px;
                            border: 1px solid #ddd;
                            background-color: #fff;
                        }}
                        .email-footer {{
                            text-align: center;
                            font-size: 0.9em;
                            color: #777;
                        }}
                        .verification-link {{
                            display: inline-block;
                            margin: 20px 0;
                            padding: 10px 20px;
                            background-color: #28a745;
                            color: #fff;
                            text-decoration: none;
                            border-radius: 5px;
                        }}
                        .verification-link:hover {{
                            background-color: #218838;
                        }}
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="email-header">
                            Verify your email address
                        </div>
                        <div class="email-body">
                            <p>Thank you for signing up at store.studyola.com!</p>
                            <p>Please click the link below to verify your email address:</p>
                            <a href="{verification_url}" class="verification-link">Verify Email</a>
                            <p>If you did not request this email, please ignore it.</p>
                        </div>
                        <div class="email-footer">
                            &copy; {timezone.now().year} store.studyola.com. All rights reserved.
                        </div>
                    </div>
                </body>
                </html>
            """
            
            try:
                send_mail(subject, message, 'support@essayfit.com', [user.email], html_message=html_message)
                logger.info(f"Verification email sent to {user.email}")
                email_sent = True
            except Exception as e:
                logger.error(f"Failed to send verification email to {user.email}: {e}")
                email_sent = False

            if email_sent:
                return Response({
                    'detail': 'Signup successful! Please verify your email to complete the registration.'
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'detail': 'Signup successful! However, we failed to send a verification email. Please try to resend the verification email.'
                }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['post'], permission_classes=[permissions.AllowAny])
    def login(self, request):
        serializer = MyTokenObtainPairSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = User.objects.get(email=request.data['email'])
        except User.DoesNotExist:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # 이메일 인증 확인
        if not user.is_email_verified:
            return Response({'detail': 'Email is not verified. Please verify your email.'}, status=status.HTTP_400_BAD_REQUEST)

        # JWT 토큰 반환
        token_data = serializer.validated_data
        
        # 사용자 정보 직렬화
        user_serializer = UserSerializer(user)

        # 마지막 로그인 업데이트
        update_last_login(None, serializer.user)

        # 응답에 JWT 토큰과 사용자 정보 추가
        response_data = {
            'token': token_data,
            'user': user_serializer.data
        }
        return Response(response_data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'], permission_classes=[permissions.IsAuthenticated])
    def logout(self, request):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "Refresh token is missing."}, status=status.HTTP_400_BAD_REQUEST)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return Response({"error": "Access token is missing."}, status=status.HTTP_400_BAD_REQUEST)

        access_token = auth_header.split()[1]
        
        try:
            self.blacklist_token(refresh_token)
            self.blacklist_access_token(access_token)
            return Response({"message": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except TokenError as e:
            return Response({"error": "Token is invalid or expired.", "details": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def blacklist_token(self, refresh_token):
        token = RefreshToken(refresh_token)
        token.blacklist()

    def blacklist_access_token(self, access_token):
        try:
            token = AccessToken(access_token)
            jti = token.get('jti')
            exp = token.get('exp')
            
            OutstandingToken.objects.filter(jti=jti).delete()
            
            OutstandingToken.objects.create(
                user_id=token['user_id'],
                jti=jti,
                token=str(token),
                created_at=timezone.now(),
                expires_at=timezone.datetime.fromtimestamp(exp, timezone.utc)
            )
            BlacklistedToken.objects.create(token=OutstandingToken.objects.get(jti=jti))
        except Exception as e:
            raise TokenError(e)

class VerifyEmail(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        code = request.query_params.get('code')
        if not code:
            return Response({'detail': 'Verification code is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uuid_code = uuid.UUID(code)
            user = User.objects.get(email_verification_code=uuid_code)
            user.is_email_verified = True
            user.email_verification_code = None
            user.save()
            return Response({'detail': 'Email verified successfully!'}, status=status.HTTP_200_OK)
        except ValueError:
            return Response({'detail': 'Invalid verification code format.'}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'detail': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordAPI(APIView):
    permission_classes = [permissions.AllowAny]

    def put(self, request):
        try:
            email = request.data.get("email")
            if not email:
                raise ValueError("Email is required.")

            user = User.objects.filter(email=email).first()
            if not user:
                raise ValueError("User with this email does not exist.")

            # Generate a temporary password
            new_password = get_random_string(length=10)
 
            # Send the temporary password via email
            subject = "[store.studyola.com] Temporary Password"
            message = f"Hello {user.username},\n\nYour temporary password is: {new_password}\n\nPlease use this password to log in and change your password immediately."
            try:
                send_mail(subject, message, 'support@essayfit.com', [email])
                logger.info(f"Temporary password sent to {email}")
            except Exception as e:
                logger.error(f"Failed to send temporary password email to {email}: {e}")
                raise ValueError("Failed to send email. Please try again later.")

            # Update the user's password
            user.set_password(new_password)
            user.save()

            return Response({"success": True}, status=status.HTTP_200_OK)
        except ValueError as e:
            return Response({"error": str(e), "success": False}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception(f"Unexpected error in ForgotPasswordAPI: {e}")
            return Response({"error": "An unexpected error occurred.", "success": False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class GoogleSignInView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = ()

    def post(self, request):
        token = request.data.get('firebase_token')        
        response, status = AccountsService.signin_user(token)
        return Response(response, status=status)


class VerifyTokenView(APIView):
    permission_classes = [permissions.AllowAny]  # 인증되지 않은 사용자도 이 엔드포인트에 접근 가능하게 설정

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({"error": "Token is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # JWT 액세스 토큰 검증
            access_token = AccessToken(token)                        
            user_id = access_token['user_id']
                        
            user = User.objects.get(id=user_id)            
            serializer = UserSerializer(user)
            
            return Response({
                "is_valid": True,
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        
        except TokenError as e:            
            return Response({"is_valid": False, "error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:            
            return Response({"is_valid": False, "error": "User does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:            
            return Response({"is_valid": False, "error": "An error occurred during token verification."}, status=status.HTTP_400_BAD_REQUEST)