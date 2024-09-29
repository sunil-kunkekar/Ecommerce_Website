# from rest_framework import viewsets, status
# from rest_framework.response import Response
# from rest_framework.permissions import IsAuthenticated, AllowAny
# from .models import User
# from .serializers import UserSerializer

# class UserViewSet(viewsets.ModelViewSet):
#     """
#     A viewset that provides the standard actions for User model.
#     Supports:
#       - GET (list, retrieve)
#       - POST (create)
#       - PUT, PATCH (update)
#       - DELETE (destroy)
#     """
#     queryset = User.objects.all()
#     serializer_class = UserSerializer

#     def get_permissions(self):
#         """
#         Set permissions based on the action.
#         - Allow anyone to create a user (POST).
#         - Other actions (GET, PUT, DELETE) require the user to be authenticated.
#         """
#         if self.action == 'create':
#             permission_classes = [AllowAny]  # Anyone can register
#         else:
#             permission_classes = [IsAuthenticated]  # Only authenticated users can access other actions
#         return [permission() for permission in permission_classes]

#     def get_queryset(self):
#         """
#         Customize queryset:
#         - Admins: Return all users.
#         - Non-admins: Return only the authenticated user's details (for retrieve).
#         """
#         if self.request.user.is_superuser:
#             return User.objects.all()  # Admins can view all users
#         elif self.action == 'list':
#             return User.objects.none()  # Non-admins cannot list all users
#         return User.objects.filter(id=self.request.user.id)

#     def create(self, request, *args, **kwargs):
#         """
#         Handle user registration.
#         - Validate input.
#         - Hash the password before saving.
#         """
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         self.perform_create(serializer)
#         headers = self.get_success_headers(serializer.data)
#         return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

#     def perform_create(self, serializer):
#         """
#         Save the user instance with hashed password.
#         """
#         user = serializer.save()
#         user.set_password(user.password)
#         user.save()

#     def list(self, request, *args, **kwargs):
#         """
#         List all users (only accessible to admins).
#         """
#         if not request.user.is_superuser:
#             return Response({'detail': 'You do not have permission to perform this action.'}, 
#                             status=status.HTTP_403_FORBIDDEN)
#         return super().list(request, *args, **kwargs)

#     def retrieve(self, request, *args, **kwargs):
#         """
#         Retrieve a specific user's information.
#         Non-admin users can only retrieve their own data.
#         """
#         instance = self.get_object()
#         serializer = self.get_serializer(instance)
#         return Response(serializer.data)



from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from .models import User
from .serializers import UserSerializer

class UserViewSet(viewsets.ModelViewSet):
    """
    A viewset that provides the standard actions for User model.
    Supports:
      - GET (list, retrieve)
      - POST (create)
      - PUT, PATCH (update)
      - DELETE (destroy)
      - JWT login (token obtain)
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_permissions(self):
        """
        Set permissions based on the action.
        - Allow anyone to create a user (POST).
        - Other actions (GET, PUT, DELETE) require the user to be authenticated.
        """
        if self.action == 'create':
            permission_classes = [AllowAny]  # Anyone can register
        else:
            permission_classes = [IsAuthenticated]  # Only authenticated users can access other actions
        return [permission() for permission in permission_classes]

    def get_queryset(self):
        """
        Customize queryset:
        - Admins: Return all users.
        - Non-admins: Return only the authenticated user's details (for retrieve).
        """
        if self.request.user.is_superuser:
            return User.objects.all()  # Admins can view all users
        elif self.action == 'list':
            return User.objects.none()  # Non-admins cannot list all users
        return User.objects.filter(id=self.request.user.id)

    def create(self, request, *args, **kwargs):
        """
        Handle user registration.
        - Validate input.
        - Hash the password before saving.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        """
        Save the user instance with hashed password.
        """
        user = serializer.save()
        user.set_password(user.password)
        user.save()

    def list(self, request, *args, **kwargs):
        """
        List all users (only accessible to admins).
        """
        if not request.user.is_superuser:
            return Response({'detail': 'You do not have permission to perform this action.'}, 
                            status=status.HTTP_403_FORBIDDEN)
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific user's information.
        Non-admin users can only retrieve their own data.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

# Token Views for login and refreshing token
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom view to obtain JWT tokens using email and password.
    """
    permission_classes = (AllowAny,)
    
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class CustomTokenRefreshView(TokenRefreshView):
    """
    View to refresh the access token.
    """
    permission_classes = (AllowAny,)
