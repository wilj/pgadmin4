import builtins
builtins.SERVER_MODE = True

from pgAdmin4 import app
from os import environ, system 
from flask import redirect, request, session
from pgadmin.tools.user_management import create_user
from pgadmin.authenticate import get_auth_sources, AuthSourceManager
from pgadmin.model import User, ServerGroup, db, Role
from pgadmin.utils import get_storage_directory
from flask_security.utils import config_value, get_post_logout_redirect, get_post_login_redirect
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)

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
    'AUTHENTICATION_SOURCES': ['oidc'],
    'SERVER_NAME': environ.get('SERVER_NAME')
})


from flask_oidc import OpenIDConnect
app.oidc = OpenIDConnect(app)
oidc = app.oidc




@app.route('/oidc_login')
@oidc.require_login
def oidc_login():

    auth_obj = AuthSourceManager(None, ['oidc'])
    print("Logging auth_obj")
    print(auth_obj)

    session['_auth_source_manager_obj'] = auth_obj.as_dict()
    print("added _auth_source_manager_obj to session")

    oidc_auth_source = get_auth_sources("oidc")
    print("Logging oidc_auth_source")
    print(oidc_auth_source)

    unique_id = "u" + oidc.user_getfield('sub') + "@cyton"
    display_name = oidc.user_getfield('preferred_username')
    email = oidc.user_getfield('email')

    if email is None or email == "None":
        email = unique_id
    
    user = User.query.filter_by(username=unique_id).first()
    
    if user is None:
        res, user = create_user({
            'username': unique_id,
            'email': email,
            'role': 2,
            'active': True,
            'is_active': True,
            'auth_source': 'oidc'
        })
    
        print("Logging res and user")
        print(res)
        print(user)

    print("querying for user")
    user = User.query.filter_by(username=unique_id).first()

    print("Logging user:")
    print(user)
    
    login_user(user, False, None, True)
    app.keyManager.set(unique_id)

    print("loading servers.json for user")

    storage_dir = get_storage_directory()
    print("storage_dir")
    print(storage_dir)
    system('rm -f ' + storage_dir + '/pgpassfile')
    system('cp /pgadmin4/pgpass/pgpassfile ' + storage_dir + '/')
    system('chmod 0600 ' + storage_dir + '/pgpassfile')

    system('/usr/local/bin/python /pgadmin4/setup.py --load-servers "' + environ.get('PGADMIN_SERVER_JSON_FILE') + '" --user ' + unique_id)

    return redirect(get_post_login_redirect())


@app.before_request
def require_login_filter():
    if request.path == "/login" and not current_user.is_authenticated:
        return redirect("/oidc_login")
