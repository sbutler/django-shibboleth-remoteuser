from __future__ import absolute_import, division, print_function, unicode_literals

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.contrib.auth.backends import RemoteUserBackend
import django.dispatch

from .models import GroupMapping

UserModel = get_user_model()

# Signals to fire to allow other people to modify the user
populate_user = django.dispatch.Signal(providing_args=['user', 'shib_meta'])


class ShibbolethRemoteUserBackend(RemoteUserBackend):
    """
    This backend is to be used in conjunction with the ``RemoteUserMiddleware``
    found in the middleware module of this package, and is used when the server
    is handling authentication outside of Django.

    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.

    Subclassers of this backend can gain more control over how the user attributes
    are set from shibboleth. Simply override ``set_user_<attrname>(user, value)``
    and it will be called from ``populate_user``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = True

    def authenticate(self, request, remote_user, shib_meta):
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

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = UserModel.objects.get_or_create(**{
                UserModel.USERNAME_FIELD: username
            })
            if created:
                user = self.configure_user(user)
        else:
            try:
                user = UserModel.objects.get(**{
                    UserModel.USERNAME_FIELD: username
                })
            except UserModel.DoesNotExist:
                pass

        if user:
            self.populate_user(user, shib_meta)
            populate_user.send(self.__class__, user=user, shib_meta=shib_meta)
            user.save()

        return user if self.user_can_authenticate(user) else None

    def populate_user(self, user, shib_meta):
        """
        Takes information from the Shibboleth metadata and populates the user
        object with it. The user will be saved by the caller after this
        completes.

        Subclassers of this backend can gain more control over how the user
        attributes are set from shibboleth. Simply override
        ``set_user_<attrname>(user, value)`` and it wil be called.
        """
        for key, value in shib_meta.items():
            if key.startswith('+'):
                # Will be handled by the signal; ignore here
                continue

            method = getattr(self, 'set_user_' + key, None)
            if method:
                method(user, value)
            elif hasattr(user, key):
                setattr(user, key, value)
            else:
                raise AttributeError("User model doesn't have attribute " + key)

    def set_user_groups(self, user, shib_groups):
        """
        Takes a list of groups information from Shibboleth and maps them to
        Django groups.
        """
        map_groupid_set = set(GroupMapping.objects.values_list('group__pk', flat=True))

        # Get a set of group ID's for the user, but only look at the ones
        # we're going to map
        user_groupid_set = set(user.groups.filter(pk__in=map_groupid_set).values_list('pk', flat=True))

        shib_groupname_set = set(shib_groups)
        shib_groupid_set = set()
        # Loop over each mapping and see if it's in our groups from Shib.
        # This will give us a Shib -> Django Group set. We try to avoid
        # fetching the entire group.
        for groupid, attr_value in GroupMapping.objects.values_list('group__pk', 'attr_value'):
            if attr_value in shib_groupname_set:
                shib_groupid_set.add(groupid)

        # Shib groups minus the user groups gives us what to add.
        add_set = shib_groupid_set - user_groupid_set
        if add_set:
            user.groups.add(*(Group.objects.filter(pk__in=add_set)))

        # User groups minus shib groups gives up what to remove.
        rem_set = user_groupid_set - shib_groupid_set
        if rem_set:
            user.groups.remove(*(Group.objects.filter(pk__in=rem_set)))
