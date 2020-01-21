from __future__ import absolute_import, division, print_function, unicode_literals

import dateutil.parser
from django.contrib import auth
from django.contrib.auth.backends import RemoteUserBackend
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib.auth import load_backend
from django.core.exceptions import ImproperlyConfigured
import logging
import time

from .app_settings import SHIB_ATTRIBUTE_MAP, SHIB_AUTHENTICATION_INSTANT

logger = logging.getLogger(__name__)


class ShibbolethRemoteUserMiddleware(RemoteUserMiddleware):
    """
    Authentication Middleware for use with Shibboleth.  Uses the recommended pattern
    for remote authentication from: http://code.djangoproject.com/svn/django/tags/releases/1.3/django/contrib/auth/middleware.py
    """

    def process_request(self, request):
        # AuthenticationMiddleware is required so that request.user exists.
        if not hasattr(request, 'user'):
            raise ImproperlyConfigured(
                "The Django remote user auth middleware requires the"
                " authentication middleware to be installed.  Edit your"
                " MIDDLEWARE_CLASSES setting to insert"
                " 'django.contrib.auth.middleware.AuthenticationMiddleware'"
                " before the RemoteUserMiddleware class.")

        #Locate the remote user header.
        try:
            username = request.META[self.header]
        except KeyError:
            # If specified header doesn't exist then remove any existing
            # authenticated remote-user, or return (leaving request.user set to
            # AnonymousUser by the AuthenticationMiddleware).
            if self.force_logout_if_no_header and request.user.is_authenticated:
                logger.info('Logging out %(username)s without header', {
                    'username': request.user.get_username(),
                })
                self.shib_remove_invalid_user(request)
            return
        # If the user is already authenticated, that user is the user we are
        # getting passed in the headers, and the IdP hasn't re-authed the user,
        # then the correct user is already persisted in the session and we don't
        # need to continue.
        try:
            shib_auth_instant_obj = dateutil.parser.parse(request.META[SHIB_AUTHENTICATION_INSTANT])
            shib_auth_instant = time.mktime(shib_auth_instant_obj.timetuple())
        except:
            # Something went wrong (ValueError, KeyError, parsing); use the old behavior
            shib_auth_instant = None
            idp_reauth = False
        else:
            sess_auth_instant = request.session.get('shib_auth_instant', 0)
            idp_reauth = shib_auth_instant > sess_auth_instant

        logger.debug('%(username)s auth instant: shib=%(shib_auth_instant)d; sess=%(sess_auth_instant)s', {
            'username': username,
            'shib_auth_instant': shib_auth_instant,
            'sess_auth_instant': sess_auth_instant,
        })

        if request.user.is_authenticated:
            if not idp_reauth and request.user.get_username() == self.clean_username(username, request):
                return
            else:
                # An authenticated user is associated with the request, but
                # it does not match the authorized user in the header.
                logger.info('Logging out %(session_username)s with stale session (idp_reauth=%(idp_reauth)s; request_username=%(request_username)s)', {
                    'idp_reauth': idp_reauth,
                    'session_username': request.user.get_username(),
                    'request_username': self.clean_username(username, request),
                })
                self.shib_remove_invalid_user(request)

        # Make sure we have all required Shiboleth elements before proceeding.
        shib_meta, error = self.parse_attributes(request)
        logger.debug('%(username)s parsed shib metadata: %(meta)r', {
            'username': username,
            'meta': shib_meta,
        })
        # Add parsed attributes to the session.
        request.session['shib'] = shib_meta
        if error:
            raise ShibbolethValidationError("All required Shibboleth elements"
                                            " not found.  %s" % shib_meta)

        # We are seeing this user for the first time in this session, attempt
        # to authenticate the user.
        logger.info('Logging in %(username)s', {
            'username': username,
        })
        user = auth.authenticate(request, remote_user=username, shib_meta=shib_meta)
        if user:
            # User is valid.  Set request.user and persist user in the session
            # by logging the user in.
            request.user = user
            if shib_auth_instant:
                request.session['shib_auth_instant'] = shib_auth_instant

            auth.login(request, user)
            # call make profile.
            self.make_profile(user, shib_meta)

    def make_profile(self, user, shib_meta):
        """
        This is here as a stub to allow subclassing of ShibbolethRemoteUserMiddleware
        to include a make_profile method that will create a Django user profile
        from the Shib provided attributes.  By default it does noting.
        """
        return

    def parse_attributes(self, request):
        """
        Parse the incoming Shibboleth attributes.
        From: https://github.com/russell/django-shibboleth/blob/master/django_shibboleth/utils.py
        Pull the mapped attributes from the apache headers.
        """
        shib_attrs = {}
        error = False
        meta = request.META
        for header, attr in SHIB_ATTRIBUTE_MAP.items():
            if len(attr) == 3:
                required, name, attr_processor = attr
            else:
                required, name = attr
                attr_processor = None

            wants_list = False
            if name.endswith('[]'):
                wants_list = True
                name = name[:-2]

            value = meta.get(header, None)
            try:
                value = value.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                pass

            if callable(attr_processor):
                # Give the user a way to massage the data from Shibboleth;
                # for example: split it into a list
                value = attr_processor(name, value)
            elif wants_list:
                # User asked for a list but didn't give us a way to make one.
                # Assume it's one of the standard Shibboleth attributes and split
                # on ';'
                value = value.split(';') if value else []

            # Check that value is a list only after the user callback.
            # Don't create a list out of a false value. If the user really
            # wants that then they can do it in their callback.
            if wants_list and value and not isinstance(value, list):
                value = [value]

            # Extend an existing list if it's present, otherwise
            # just set the value.
            if wants_list and name in shib_attrs:
                shib_attrs[name].extend(value)
            else:
                shib_attrs[name] = value

            if not value or value == '':
                if required:
                    error = True

        return shib_attrs, error

    def shib_remove_invalid_user(self, request):
        """
        Removes the current authenticated user in the request which is invalid
        but only if the user is authenticated via the RemoteUserBackend.

        This is a copy of the function from RemoteUserMiddleware, but that is
        "private" so copy it hear.
        """
        try:
            stored_backend = load_backend(request.session.get(auth.BACKEND_SESSION_KEY, ''))
        except ImportError:
            # backend failed to load
            auth.logout(request)
        else:
            if isinstance(stored_backend, RemoteUserBackend):
                auth.logout(request)

class ShibbolethValidationError(Exception):
    pass
