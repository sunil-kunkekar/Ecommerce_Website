from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate

from .models import User
from .serializers import (
    UserRegistrationSerializer,
    LoginSerializer,
    UserProfileSerializer,
    UserChangePasswordSerializer,
    SendPasswordResetEmailSerializer,
    UserPasswordResetSerializer
)

# Utility function to generate JWT tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# 1. User Registration View
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import UserRegistrationSerializer, UserProfileSerializer
from .models import User
from .renderers import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import UserRegistrationSerializer
from .models import User  # Ensure you import your User model
from .renderers import UserRenderer  # Import your custom renderer

class UserRegistrationView(APIView):
    """
    A view that supports both user registration (POST) and user list retrieval (GET) for admin users.
    """
    renderer_classes = [UserRenderer]
    permission_classes = [permissions.AllowAny]  # Allow any user to register

    def post(self, request, format=None):
        """
        Handles user registration.
        """
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Optionally generate a token for the registered user
        token = get_tokens_for_user(user)  
        return Response({
            'token': token, 
            'msg': 'Registration Successful'
        }, status=status.HTTP_201_CREATED)

    def get(self, request, format=None):
        """
        Retrieve a list of users (accessible only to admins).
        """
        if not request.user.is_superuser:
            return Response({'detail': 'You do not have permission to view this.'}, status=status.HTTP_403_FORBIDDEN)

        # Retrieve all users if the request user is an admin
        users = User.objects.all()  # Corrected from User().objects.all() to User.objects.all()
        serializer = UserRegistrationSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    

# 2. Login View (JWT Authentication)
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import LoginSerializer
from .utils import get_tokens_for_user  # Ensure you have this utility to generate tokens

class LoginView(APIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)  # This will raise an error if validation fails
        user = serializer.validated_data['user']
        
        # Get or generate JWT token for the user
        token = get_tokens_for_user(user)

        return Response({
            'token': token,
            'msg': 'Login successful'
        }, status=status.HTTP_200_OK)








# 3. User Profile View (Accessible only by authenticated users)
class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# 4. Change Password View
class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = UserChangePasswordSerializer(data=request.data, context={'user': request.user})
        if serializer.is_valid():
            return Response({'msg': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 5. Send Password Reset Email View
class SendPasswordResetEmailView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'msg': 'Password reset link sent. Please check your email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 6. Password Reset View
class UserPasswordResetView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uid, token, *args, **kwargs):
        serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
        if serializer.is_valid():
            return Response({'msg': 'Password reset successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
