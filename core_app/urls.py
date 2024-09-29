from django.urls import path,include
from django.contrib import admin
admin.site.site_header = "Ecommerce Admin"
admin.site.site_title  = "Ecommerce TOOL"
admin.site.index_title = "Ecommerce"


from rest_framework.routers import DefaultRouter
from .views import *

# Create a router and register the UserViewSet
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')

# Wire up the API using automatic URL routing.
urlpatterns = [
    path('', include(router.urls)),
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),  # Login for JWT tokens
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),  # Refresh token
]



