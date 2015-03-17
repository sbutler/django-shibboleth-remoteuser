import dateutil.parser
from django.contrib import auth
from django.contrib.auth.backends import RemoteUserBackend
from django.contrib.auth.middleware import RemoteUserMiddleware
from django.contrib.auth import load_backend
from django.core.exceptions import ImproperlyConfigured
import time

from shibboleth.app_settings import SHIB_ATTRIBUTE_MAP, SHIB_SESSION_ATTRS, LOGOUT_SESSION_KEY, SHIB_AUTHENTICATION_INSTANT

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

        #To support logout.  If this variable is True, do not
        #authenticate user and return now.
        if request.session.get(LOGOUT_SESSION_KEY) == True:
            return
        else:
            #Delete the shib reauth session key if present.
	    request.session.pop(LOGOUT_SESSION_KEY, None)

        #Locate the remote user header.
        try:
            username = request.META[self.header]
        except KeyError:
            # If specified header doesn't exist then remove any existing
            # authenticated remote-user, or return (leaving request.user set to
            # AnonymousUser by the AuthenticationMiddleware).
            if request.user.is_authenticated():
                try:
                    stored_backend = load_backend(request.session.get(
                        auth.BACKEND_SESSION_KEY, ''))
                    if isinstance(stored_backend, RemoteUserBackend):
                        auth.logout(request)
                except ImproperlyConfigured as e:
                    # backend failed to load
                    auth.logout(request)
            return

        username = self.clean_username(username, request)

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

        if request.user.is_authenticated():
            # Backwards compatable for new Django custom User models
            try:
                request_username = request.user.get_username()
            except AttributeError:
                request_username = request.user.username

            if not idp_reauth and request_username == username:
                return

        # Make sure we have all required Shiboleth elements before proceeding.
        shib_meta, error = self.parse_attributes(request)
        # Add parsed attributes to the session. Only do this if requested since
        # it can bloat the session storage.
        if SHIB_SESSION_ATTRS:
            request.session['shib'] = shib_meta
        if error:
            raise ShibbolethValidationError("All required Shibboleth elements"
                                            " not found.  %s" % shib_meta)

        # We are seeing this user for the first time in this session, attempt
        # to authenticate the user.
        user = auth.authenticate(remote_user=username, shib_meta=shib_meta)
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
            required, name = attr

            wants_list = False
            if name.endswith('[]'):
                wants_list = True
                name = name[:-2]

            value = meta.get(header, None)
            if len(attr) > 2 and callable(attr[2]):
                # Give the user a way to massage the data from Shibboleth;
                # for example: split it into a list
                value = callable(name=name, value=attr[2])
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

            # If we're looking at the username attribute, clean it
            if name == 'username':
                value = self.clean_username(value, request)

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

class ShibbolethValidationError(Exception):
    pass
