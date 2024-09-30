from django.contrib import admin
from core_app.models import *
from django.utils.translation import gettext_lazy as _


class UserAdmin(admin.ModelAdmin):
    # Define the fields to be displayed in the admin list view
    list_display = ('id','email', 'name', 'is_admin', 'is_active', 'tc')
    
    # Define fields that can be searched
    search_fields = ('email', 'name')

    # Add filters to the right sidebar
    list_filter = ('is_admin', 'is_active', 'tc')

    # Add pagination to the admin interface
    list_per_page = 20

    # Allow editing users directly in the list view
    ordering = ('email',)

    # Define fieldsets for editing user details
    fieldsets = (
        (None, {
            'fields': ('email', 'name', 'password', 'tc')
        }),
        (_('Permissions'), {
            'fields': ('is_active', 'is_admin', 'groups', 'user_permissions')
        }),
    )

    # Use this method to hash the password before saving
    def save_model(self, request, obj, form, change):
        if obj.password:
            obj.set_password(obj.password)  # Ensure password is hashed
        super().save_model(request, obj, form, change)

    # Customize form layout
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        # You can add any custom modifications to the form here
        return form

# Register the User model with the custom UserAdmin
admin.site.register(User, UserAdmin)
