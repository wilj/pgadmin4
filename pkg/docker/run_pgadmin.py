import builtins
builtins.SERVER_MODE = True

from pgAdmin4 import app
from os import environ 

keycloak = environ.get('OIDC_KEYCLOAK_CLIENT_SECRETS')

print("Using Keycloak config file: " + keycloak)
app.config.update({
    'TESTING': True,
    'DEBUG': True,
    'OIDC_ID_TOKEN_COOKIE_SECURE': True,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'SECRET_KEY': environ.get('SECRET_KEY'),
    'OIDC_KEYCLOAK_CLIENT_SECRETS': keycloak,
    'OIDC_CLIENT_SECRETS': environ.get('OIDC_CLIENT_SECRETS'),
    'SERVER_NAME': environ.get('SERVER_NAME')
})


from flask_oidc import OpenIDConnect
app.oidc = OpenIDConnect(app)
oidc = app.oidc
