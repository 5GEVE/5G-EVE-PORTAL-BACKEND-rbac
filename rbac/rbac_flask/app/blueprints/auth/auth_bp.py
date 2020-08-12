from flask import ( Blueprint, jsonify, request )
from app import oidc, config
#from flask_jwt_extended import ( jwt_optional, get_jwt_identity )

from app.keycloak.keycloak_client import Keycloak
from app.mail.mail import MailManager

import requests, json, os
from requests.auth import HTTPBasicAuth

# BLUEPRINT CREATION
bp = Blueprint('auth', __name__, url_prefix='/portal/rbac')

# Keycloak adapter
kc_client = Keycloak()

# Email manager
mail_manager = MailManager()

# Bugzilla URL
BZ_URL = config['bz_url']

# ROUTES DEFINITION
@bp.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400
    try:
        data = request.get_json()
    except Exception as e:
        return jsonify({"details": "Provided JSON cannot be decoded"}), 400

    if 'email' not in data.keys() or 'password' not in data.keys():
        return jsonify({"details": "Username or password not provided"}), 400
    
    status_code, msg = kc_client.get_auth_token(data['email'], data['password'])
    
    if status_code == requests.codes.ok:
        user_credentials = {'email': data['email'], 'password': data['password']}
        headers = {'Content-Type': 'application/json'}
        bz_url = "{}{}".format(BZ_URL, "login")
        
        bz_login_response = requests.post(bz_url, headers=headers, json=user_credentials)

        if bz_login_response.status_code == requests.codes.ok:
            # Check if user account is already enabled
            status_code_token_to_user, user_data = kc_client.token_to_user(msg['access_token'])
            
            if "enabled" not in user_data['roles']:
                return jsonify({"details": "User account not activated. Please, wait until the administrator validates your account"}), 250
            else:
                return msg, status_code
        else:
            return bz_login_response.json(), bz_login_response.status_code

    return msg, status_code

@bp.route('/refreshtoken', methods=['POST'])
def refresh_token():
    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400

    data = request.get_json()
    if 'refresh_token' not in data.keys():
        return jsonify({"details": "refresh_token not provided"}), 400
    
    status_code, details = kc_client.refresh_token(data['refresh_token'])

    return details, status_code

@bp.route('/register', methods=['POST'])
def registration():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400
    
    data = request.get_json()
    try:
        # Default: disabled user
        data['roles'].append("disabled")
        status_code, details = kc_client.create_user(data['email'], data['username'], data['firstName'], data['lastName'], data['password'], data['roles'])
    except KeyError as error:
        return jsonify({"details": "Parameter {} not provided".format(error)}), 400

    if status_code in [200, 201]:
        bugzilla_url = "{}{}".format(BZ_URL, "register")
        bz_data = {'email': data['email'], 'full_name': data['firstName'] + " " + data['lastName'], 'password': data['password']}
        bz_registration_reply = requests.post(bugzilla_url, headers=request.headers, data=json.dumps(bz_data))
        
        if bz_registration_reply.status_code not in [200, 201]:
            
            kc_client.delete_user(details['user_id'])
            return bz_registration_reply.json(), bz_registration_reply.status_code

        # Add associated project to user
        try:
            project = []
            project.append(data['project'])
            status_code, msg = kc_client.add_user_attributes(details['user_id'], "project", project)
        except KeyError as error:
            return jsonify({"details": "Error adding project: {}".format(error)}), 400

        # Create a ticket if correctly created user
        bz_trusted_url = "{}{}".format(BZ_URL, "portal/tsb/tickets/trusted")
        bz_trusted_data = {
            'reporter': config['tickets_admin'], 
            'product': config['tickets_product'], 
            'component': config['tickets_component'], 
            'summary': "Registration complete: {}".format(data['email']), 
            'description': "User {} should be enabled to be able to use the portal".format(data['email']),
            'assigned_to': config['portal_admin']}
        bz_ticket_reply = requests.post(bz_trusted_url, headers=request.headers, data=json.dumps(bz_trusted_data))

        return jsonify({'details': details}), bz_registration_reply.status_code

    return details, status_code

@bp.route('/logout', methods=['GET'])
@oidc.accept_token(require_token=True)
def logout():
    token = str(request.headers['authorization']).split(" ")[1]
    
    status_code ,msg = kc_client.get_user_id(token)
    
    if status_code == requests.codes.ok:
        if 'sub' in msg.keys():
            user_id = msg['sub']
            status_code, msg = kc_client.logout(user_id)

            return msg, status_code

        elif 'active' in msg.keys():
            return jsonify({"details": "Expired token"}), 401       
    
    return msg, status_code

'''
@bp.route('/forgotpassword', methods=['POST'])
#@oidc.accept_token(require_token=True)
def forgot_password():

    if not request.is_json:
        return jsonify({"details": "No json provided"}), 400

    data = request.get_json()

    #token = str(request.headers['authorization']).split(" ")[1]

    #status_code_token_to_user, user_data = kc_client.token_to_user(msg['access_token'])
    #print(user_data)

    try:
        email = data['email']
    except KeyError as error:
        return jsonify({"details": "Parameter {} not provided".format(error)}), 400

    status_code ,msg = kc_client.get_user_by_email(email)

    if status_code == requests.codes.ok:
        print(msg)
        msg = json.loads(msg.decode('utf-8'))
        
        if 'id' in msg[0].keys():
            user_id = msg[0]['id']

            # Generate new password
            stream = os.popen('openssl rand -hex 8')
            new_password = str(stream.read()).rstrip()

            bugzilla_url = "{}{}".format(BZ_URL, "changepassword")
            user_data = {"user_email": email,"new_password": new_password}
            bz_reply = requests.put(bugzilla_url, headers=request.headers, data=json.dumps(user_data))

            if bz_reply.status_code in [200, 201, 204]:

                status_code, msg = kc_client.change_password(user_id, new_password)

                mail_manager.send_pass_reset_email(email, new_password)

                return jsonify({"details": ""}), status_code

            else:
                return jsonify({"details": bz_reply.json()}), bz_reply.status_code

        else:
            print("[ERROR][FORGOTPASS] user correctly retrieved from keycloak by no id assotiated")
            return jsonify({"details": "Internal server error"}), 500
    else:
        return jsonify({"details": msg}), status_code
'''

@bp.route('/realmroles', methods=['GET'])
def get_realm_roles():
    status_code, msg = kc_client.get_available_roles()
    
    return jsonify({"details": msg}), status_code


#### For testing purposes ####

@bp.route('/roles', methods=['GET'])
@oidc.accept_token(require_token=True)
def get_roles():
    token = str(request.headers['authorization']).split(" ")[1]
    user_id = kc_client.get_user_id(token)
    status, msg = kc_client.get_user_roles(user_id)

    return msg, status

@bp.route('/isvalid', methods=['GET'])
@oidc.accept_token(require_token=True)
def is_valid():
    return jsonify({'msg': 'Token accepted'}), 200
