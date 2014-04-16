from django.contrib.auth.models import User, Group
from django.contrib.auth.backends import ModelBackend
import django.dispatch

# Support Django 1.5's custom user models
# From: django-auth-ldap/django_auth_ldap/backend.py?at=default
try:
    from django.contrib.auth import get_user_model
except ImportError:
    get_user_model = lambda: User


# Signals to fire to allow other people to modify the user
populate_user = django.dispatch.Signal(providing_args=['user', 'shib_meta'])


class ShibbolethRemoteUserBackend(ModelBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of this package, and is used when the server
    is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = True

    def authenticate(self, remote_user, shib_meta):
        """
        The username passed as ``remote_user`` is considered trusted.  This
        method simply returns the ``User`` object with the given username,
        creating a new ``User`` object if ``create_unknown_user`` is ``True``.

        Returns None if ``create_unknown_user`` is ``False`` and a ``User``
        object with the given username is not found in the database.
        """

	if not remote_user:
            return
        user = None
        username = self.clean_username(remote_user)

        UserModel = get_user_model()
        # Backwards compatable for custom User models
        username_field = getattr(UserModel, 'USERNAME_FIELD', 'username')

	# Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = UserModel.objects.get_or_create(**{
                username_field: username
            })
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = UserModel.objects.get(**{
                    username_field: username
                })
            except User.DoesNotExist:
                pass

        if user:
            self.populate_user(user, shib_meta)
            populate_user.send(self.__class__, user=user, shib_meta=shib_meta)
            user.save()

        return user

    def clean_username(self, username):
        """
        Performs any cleaning on the "username" prior to using it to get or
        create the user object.  Returns the cleaned username.

        By default, returns the username unchanged.
        """
        return username
    
    def configure_user(self, user):
        """
        Configures a user after creation and returns the updated user.

        By default, returns the user unmodified.
        """
        return user

    def populate_user(self, user, shib_meta):
        """
        Takes information from the Shibboleth metadata and populates the user
        object with it. The user will be saved by the caller after this
        completes.
        """
        for key, value in shib_meta.items():
            if key == 'groups':
                self.sync_groups(user, value)
            elif hasattr(user, key):
                setattr(user, key, value)

    def sync_user_groups(self, user, shib_groups):
        """
        Takes a list of groups information from Shibboleth and maps them to
        Django groups.
        """
        pass
