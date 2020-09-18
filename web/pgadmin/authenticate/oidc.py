##########################################################################
#
# pgAdmin 4 - PostgreSQL Tools
#
# Copyright (C) 2013 - 2020, The pgAdmin Development Team
# This software is released under the PostgreSQL Licence
#
##########################################################################

"""A blueprint module implementing the ldap authentication."""

import ssl
import config

from flask_babelex import gettext
from urllib.parse import urlparse

from .internal import BaseAuthentication
from pgadmin.model import User, ServerGroup, db, Role
from flask import current_app
from pgadmin.tools.user_management import create_user



class OIDCAuthentication(BaseAuthentication):
    """OIDC Authentication Class"""

    def get_friendly_name(self):
        return gettext("oidc")

    def authenticate(self, form):
        return True, None
    