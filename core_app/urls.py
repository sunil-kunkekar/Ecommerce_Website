from django.urls import path,include
from django.contrib import admin
admin.site.site_header = "Ecommerce Admin"
admin.site.site_title  = "Ecommerce TOOL"
admin.site.index_title = "Ecommerce"


# from rest_framework.routers import DefaultRouter
# from .views import *

# # Create a router and register the UserViewSet
# router = DefaultRouter()
# router.register(r'users', UserViewSet, basename='user')

# Wire up the API using automatic URL routing.



from django.urls import path
from .views import (
    UserRegistrationView,
    LoginView,
    UserProfileView,
    ChangePasswordView,
    SendPasswordResetEmailView,
    UserPasswordResetView
)

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('User_Login/',LoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),
]
