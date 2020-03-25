import os, json

basedir = os.path.abspath(os.path.dirname(__file__))

def configure(mode, app):

    if mode == "DEV":

        # APP configuration
        app.config['DEBUG'] = True
        app.config['SECRET_KEY'] = 'you-will-never-guess'
        app.config['CORS_HEADERS'] = 'Content-Type'

        # OpenIDConnect configuration
        app.config['OIDC_CLIENT_SECRETS'] = '{}/keycloak/keycloak.json'.format(basedir)
        app.config['OIDC_INTROSPECTION_AUTH_METHOD'] = 'client_secret_post'
        app.config['OIDC_TOKEN_TYPE_HINT'] = 'access_token'
        app.config['OIDC_ID_TOKEN_COOKIE_SECURE'] = False
        app.config['OIDC_REQUIRE_VERIFIED_EMAIL'] = False
        app.config['OIDC_USER_INFO_ENABLED'] = True
        app.config['OIDC_OPENID_REALM'] = '5geve'
        app.config['OIDC_SCOPES'] = ['openid', 'email', 'profile']
        app.config['OIDC_RESOURCE_CHECK_AUD'] = True
        app.config['OIDC_CLOCK_SKEW'] = 560 #iat must be > time.time() - OIDC_CLOCK_SKEW
        app.config['OIDC_RESOURCE_SERVER_ONLY'] = True

    # Create keycloak configuration file
    with open(os.path.abspath(os.path.dirname(__file__))+'/../app/flask_config.json', 'r') as config_file:
        config = config_file.read()

    conf = json.loads(config)

    kc_config = {}
    kc_config['web'] = {}
    # Keycloak trusted client configuration
    kc_config['web']['client_id'] = conf['kc_client_id']
    kc_config['web']['client_secret'] = conf['kc_client_secret']
    # oidc package and admin URLs 
    kc_config['web']['issuer'] = "{}{}".format(conf['kc_url'], conf['issuer'])
    kc_config['web']['redirect_uris'] = []
    kc_config['web']['redirect_uris'].append("{}{}".format(conf['kc_url'], conf['redirect_uris'][0]))
    kc_config['web']['auth_uri'] = "{}{}".format(conf['kc_url'], conf['auth_uri'])
    kc_config['web']['userinfo_uri'] = "{}{}".format(conf['kc_url'], conf['userinfo_uri'])
    kc_config['web']['token_uri'] = "{}{}".format(conf['kc_url'], conf['token_uri'])
    kc_config['web']['token_introspection_uri'] = "{}{}".format(conf['kc_url'], conf['token_introspection_uri'])
    kc_config['web']['end_session'] = "{}{}".format(conf['kc_url'], conf['end_session'])
    kc_config['web']['admin_username'] = "{}".format(conf['kc_admin_username'])
    kc_config['web']['admin_password'] = "{}".format(conf['kc_admin_password'])
    kc_config['web']['admin_token_uri'] = "{}{}".format(conf['kc_url'], conf['admin_token_uri'])
    kc_config['web']['admin_token_introspect_uri'] = "{}{}".format(conf['kc_url'], conf['admin_token_introspect_uri'])
    kc_config['web']['admin_users_uri'] = "{}{}".format(conf['kc_url'], conf['admin_users_uri'])
    kc_config['web']['admin_groups_uri'] = "{}{}".format(conf['kc_url'], conf['admin_groups_uri'])
    kc_config['web']['admin_roles_uri'] = "{}{}".format(conf['kc_url'], conf['admin_roles_uri'])

    with open(os.path.abspath(os.path.dirname(__file__))+'/../app/keycloak/keycloak.json',"w+") as f:
        json.dump(kc_config, f)

             
