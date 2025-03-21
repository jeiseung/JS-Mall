from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

class CustomJWTAuthentication(JWTAuthentication):
    def get_validated_token(self, raw_token):
        token = super().get_validated_token(raw_token)        
        if BlacklistedToken.objects.filter(token__jti=token['jti']).exists():
            raise AuthenticationFailed('This token has been blacklisted.')
        return token
