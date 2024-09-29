from rest_framework import serializers
from .models import User  # Import the custom User model
from django.contrib.auth.password_validation import validate_password
from rest_framework.validators import UniqueValidator

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model to handle user data.
    """

    # Email validation to ensure uniqueness
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    # Password field (write-only)
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password],
        style={'input_type': 'password'}
    )

    # Terms and conditions field (must be True)
    tc = serializers.BooleanField(
        required=True,
        label="Terms and Conditions accepted"
    )

    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'password', 'tc']
        extra_kwargs = {
            'password': {'write_only': True},  # Password should not be readable
        }

    # Create method to handle new user creation
    def create(self, validated_data):
        """
        Create and return a new user instance, after hashing the password.
        """
        user = User(
            email=validated_data['email'],
            name=validated_data['name'],
            tc=validated_data['tc']
        )
        user.set_password(validated_data['password'])  # Hashing the password
        user.save()
        return user

    # Update method to handle updating existing user
    def update(self, instance, validated_data):
        """
        Update and return an existing user instance, updating password if provided.
        """
        instance.email = validated_data.get('email', instance.email)
        instance.name = validated_data.get('name', instance.name)
        instance.tc = validated_data.get('tc', instance.tc)

        # Check if password is being updated
        password = validated_data.get('password', None)
        if password:
            instance.set_password(password)  # Hash the new password

        instance.save()
        return instance
