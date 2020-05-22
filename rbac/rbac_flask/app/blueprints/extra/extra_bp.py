from flask import ( Blueprint, jsonify, request )
from app import oidc, config
#from flask_jwt_extended import ( jwt_optional, get_jwt_identity )

from app.keycloak.keycloak_client import Keycloak

import requests, json, collections
from requests.auth import HTTPBasicAuth

# BLUEPRINT CREATION
bp = Blueprint('extra', __name__, url_prefix='/portal/rbac/extra')

# Keycloak adapter
kc_client = Keycloak()

# Bugzilla URL
BZ_URL = config['bz_url']

# ROUTES DEFINITION
""" 
    Retrieves available roles
"""
@bp.route('/realmroles', methods=['GET'])
def get_realm_roles():
    status_code, msg = kc_client.get_available_roles()
    
    return jsonify({"details": msg}), status_code

##########################
## Use cases management ##
##########################

@bp.route('/use-cases', methods=['GET'])
@oidc.accept_token(require_token=True)
def get_use_cases():

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        status_code, msg = kc_client.get_user_attributes(msg['id'], "use_cases")
    
    return jsonify({"details": msg}), status_code

@bp.route('/use-cases', methods=['POST'])
@oidc.accept_token(require_token=True)
def add_use_cases():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400
    
    data = request.get_json()
    try:
        if not data['use_cases']:
            return jsonify({"details": "No use cases provided"}), 400
    except Exception as e:
        return jsonify({"details": "use_cases key not found at the provided JSON"}), 400
    
    if not type(data['use_cases']) == list:
        return jsonify({"details": "Use cases must be provided using a list of elements"}), 400

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        status_code, msg = kc_client.add_user_attributes(msg['id'], "use_cases", data['use_cases'])

    return jsonify({"details": msg}), status_code

@bp.route('/use-cases', methods=['DELETE'])
@oidc.accept_token(require_token=True)
def delete_use_cases():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400

    data = request.get_json()
    if not data['use_cases']:
        return jsonify({"details": "No use cases provided"}), 400

    if not type(data['use_cases']) == list:
        return jsonify({"details": "Use cases must be provided using a list of elements"}), 400

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        status_code, msg = kc_client.delete_user_attributes(msg['id'], "use_cases", data['use_cases'])

    return jsonify({"details": msg}), status_code

###################
## Managed sites ##
###################
@bp.route('/managed-sites', methods=['GET'])
@oidc.accept_token(require_token=True)
def get_managed_sites():

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        if "SiteManager" in msg['roles']:
            status_code, msg = kc_client.get_user_attributes(msg['id'], "managed_sites")
        else:
            msg = {"managed_sites": []}
            status_code = 200
    
    return jsonify({"details": msg}), status_code

@bp.route('/managed-sites', methods=['POST'])
@oidc.accept_token(require_token=True)
def add_managed_sites():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400
    
    data = request.get_json()
    try:
        if not data['managed_sites']:
            return jsonify({"details": "No use cases provided"}), 400
    except Exception as e:
        return jsonify({"details": "managed_sites key not found at the provided JSON"}), 400
    
    if not type(data['managed_sites']) == list:
        return jsonify({"details": "Use cases must be provided using a list of elements"}), 400

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        if "SiteManager" in msg['roles']:
            status_code, msg = kc_client.add_user_attributes(msg['id'], "managed_sites", data['managed_sites'])
        else:
            msg = {"managed_sites": []}
            status_code = 200        

    return jsonify({"details": msg}), status_code

@bp.route('/managed-sites', methods=['DELETE'])
@oidc.accept_token(require_token=True)
def delete_managed_sites():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400

    data = request.get_json()
    if not 'managed_sites' in data.keys():
        return jsonify({"details": "No use cases provided"}), 400

    if not type(data['managed_sites']) == list:
        return jsonify({"details": "Use cases must be provided using a list of elements"}), 400

    token = str(request.headers['authorization']).split(" ")[1]

    status_code, msg = kc_client.token_to_user(token)
    if status_code == requests.codes.ok:
        if "SiteManager" in msg['roles']:
            status_code, msg = kc_client.delete_user_attributes(msg['id'], "managed_sites", data['managed_sites'])
        else:
            msg = {"managed_sites": []}
            status_code = 200         

    return jsonify({"details": msg}), status_code

#### For testing purposes ####

@bp.route('/services', methods=['GET'])
@oidc.accept_token(require_token=True)
def services():

    token = str(request.headers['authorization']).split(" ")[1]
    status_code, msg = kc_client.token_to_user(token)
    
    if status_code == requests.codes.ok:
    
        if "5geve_admin" in msg['roles']:
            services = [{'name':'Experiments'}, {'name': 'VNF Storage'}, {'name': 'Services Catalogue'}, {'name': 'Tickets'}]
        elif "5geve_experimenter" in msg['roles']:
            services = [{'name':'Experiments'}, {'name': 'Services Catalogue'}, {'name': 'Tickets'}]
        elif "5geve_vnfdev" in msg['roles']:
            services = [{'name': 'VNF Storage'}, {'name': 'Tickets'}]
        else:
            services = [{}]

        return jsonify({'details': services}), status_code
        
    return msg, status_code
