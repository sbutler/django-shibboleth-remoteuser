from __future__ import absolute_import, division, print_function, unicode_literals

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

#At a minimum you will need username,
default_shib_attributes = {
  "Shibboleth-eppn": (True, "username"),
}

SHIB_ATTRIBUTE_MAP = getattr(settings, 'SHIBBOLETH_ATTRIBUTE_MAP', default_shib_attributes)
# When the user last auth'ed to the IdP. Used to determine if we should
# re-login the user. Probably don't need to change this.
SHIB_AUTHENTICATION_INSTANT = getattr(settings, 'SHIBBOLETH_AUTHENTICATION_INSTANT', 'Shib-Authentication-Instant')
#Set to true if you are testing and want to insert sample headers.
SHIB_MOCK_HEADERS = getattr(settings, 'SHIBBOLETH_MOCK_HEADERS', False)

LOGIN_URL = getattr(settings, 'LOGIN_URL', None)

if not LOGIN_URL:
    raise ImproperlyConfigured("A LOGIN_URL is required.  Specify in settings.py")

#Optional logout parameters
#This should look like: https://sso.school.edu/idp/logout.jsp?return=%s
#The return url variable will be replaced in the LogoutView.
LOGOUT_URL = getattr(settings, 'SHIBBOLETH_LOGOUT_URL', None)
#LOGOUT_REDIRECT_URL specifies a default logout page that will always be used when
#users logout from Shibboleth.
LOGOUT_REDIRECT_URL = getattr(settings, 'SHIBBOLETH_LOGOUT_REDIRECT_URL', None)


