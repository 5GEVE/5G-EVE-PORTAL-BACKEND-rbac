import os, json

basedir = os.path.abspath(os.path.dirname(__file__))

def configure(mode, app):
    #app.config['SERVER_NAME'] = "0.0.0.0:8090"

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

             
