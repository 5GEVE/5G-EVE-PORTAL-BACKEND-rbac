import os, json
from flask import Flask
from .config import configure

from flask_oidc import OpenIDConnect

from flask_cors import CORS

oidc = OpenIDConnect()

with open(os.path.abspath(os.path.dirname(__file__))+'/flask_config.json', 'r') as conf_file:
    conf = conf_file.read()

config = json.loads(conf)

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    configure("DEV", app)
    CORS(app, resources={r"/*": {"origins": "*"}})
    with app.app_context():
        # Imports
        from .blueprints.auth.auth_bp import bp as auth_bp       
        
        # OpenIDConnect initialization
        oidc.init_app(app)

        app.register_blueprint(auth_bp)

        return app
