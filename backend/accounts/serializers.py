from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email','start_date','last_login']
        
class UpdateUsernameSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username']
        extra_kwargs = {
            'username': {'required': True}
        }

    def validate_username(self, value):
        if User.objects.filter(username=value).exclude(id=self.instance.id).exists():
            raise serializers.ValidationError("This username is already taken. Please choose a different one.")
        return value

class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered. Please use a different email.")
        return value

    def save(self, **kwargs):
        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if password != password2:
            raise serializers.ValidationError({'error': 'Passwords did not match'})

        user = User(
            email=self.validated_data['email'],
            username=self.validated_data['username'],
            is_active=True
        )
        user.set_password(self.validated_data['password'])
        user.save()
        return user

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Custom claims
        token['email'] = user.email
        return token
 