from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models

# Custom User Manager
class UserManager(BaseUserManager):
    def create_user(self, email, name, tc, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not name:
            raise ValueError("Users must have a name")
        if not tc:
            raise ValueError("Users must accept terms and conditions")

        email = self.normalize_email(email)
        user = self.model(email=email, name=name, tc=tc)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        user = self.create_user(email, name, tc=True, password=password)
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


# Custom User Model
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    tc = models.BooleanField(default=False, verbose_name="Terms and Conditions accepted")
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    # Related name added to avoid conflict with Django's default auth.User model
    groups = models.ManyToManyField(
        'auth.Group', 
        related_name='custom_user_set', 
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission', 
        related_name='custom_user_permissions_set', 
        blank=True
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'tc']

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin
