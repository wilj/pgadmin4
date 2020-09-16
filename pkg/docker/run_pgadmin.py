import builtins
builtins.SERVER_MODE = True

from pgAdmin4 import app
from os import environ 
from flask import redirect, request

keycloak = environ.get('OIDC_KEYCLOAK_CLIENT_SECRETS')

print("Using Keycloak config file: " + keycloak)
app.config.update({
    'WTF_CSRF_CHECK_DEFAULT': False,
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


@app.route('/oidc_login')
@oidc.require_login
def oidc_login():
    return 'Welcome %s' % oidc.user_getfield('email')


@app.before_request
def require_login_filter():
    if request.path == "/login":
        return redirect("/oidc_login")
# @app.before_request
# def do_login():
#         print("ATTEMPTING REDIRECT TO OIDC SERVER")
#         return oidc.redirect_to_auth_server(None, None)

