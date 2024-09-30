from rest_framework import serializers
from .models import User
from django.utils.translation import gettext_lazy as _
from django.contrib.auth import authenticate


class UserRegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'password', 'confirm_password', 'tc']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError(_("Password and Confirm Password don't match"))

        return attrs

    def create(self, validated_data):
        # Remove confirm_password from validated_data
        validated_data.pop('confirm_password')

        # Create the user
        user = User(**validated_data)  # Use the ** operator to unpack validated_data

        # Set the password and save the user
        user.set_password(validated_data['password'])
        user.save()

        return user


from django.contrib.auth import authenticate

from django.contrib.auth import authenticate
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type': 'password'}, trim_whitespace=False)

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        # Authenticate the user
        user = authenticate(request=self.context.get('request'), email=email, password=password)

        if user is None:
            raise serializers.ValidationError(_("Unable to log in with provided credentials."), code='authorization')

        attrs['user'] = user
        return attrs




class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'role', 'avatar1', 'location', 'content_category']


from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            link = f'http://localhost:1001/api/User/reset-password/{uid}/{token}'
            body = f'Click the following link to reset your password: {link}'
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email,
            }
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError(_("You are not a registered user"))

class UserChangePasswordSerializer(serializers.Serializer):
    password         = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)

    class Meta:
        fields = ['password', 'confirm_password']

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        user = self.context.get('user')

        if password != confirm_password:
            raise serializers.ValidationError(_("Password and Confirm Password don't match"))

        user.set_password(password)
        user.save()
        return attrs


from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class UserPasswordResetSerializer(serializers.Serializer):
    password         = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    confirm_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'confirm_password']

    def validate(self, attrs):
        try:
            password         = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            uid              = self.context.get('uid')
            token            = self.context.get('token')

            if password != confirm_password:
                raise serializers.ValidationError(_("Password and Confirm Password don't match"))

            user_id = smart_str(urlsafe_base64_decode(uid))
            user    = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError(_('Token is not valid or has expired'))

            user.set_password(password)
            user.save()
            return attrs

        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError(_('Token is not valid or has expired'))
