import requests, os, json
from requests.auth import HTTPBasicAuth
from flask import ( jsonify )

#TODO:
ENGINE_ADDRESS = "http://192.168.1.251:8080"

class Keycloak:

    def __init__(self):
        with open(os.path.abspath(os.path.dirname(__file__))+'/keycloak.json') as config:
            self.client_config = json.load(config)

        self.user_tokens = {}
        self.user_details = {}
        self.admin_access_token, self.admin_refresh_token = self.admin_token()

    def admin_token(self):
        data = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': self.client_config['web']['admin_username'],
            'password': self.client_config['web']['admin_password']
        }
        response = requests.post(self.client_config['web']['admin_token_uri'], data=data)

        if response.status_code != requests.codes.ok:
            print("\tSERVER > [ERROR] Admin token not correctly requested - {}".format(response.json()))
            return None, None
        else:
            response_data = response.json()
            return response_data['access_token'], response_data['refresh_token']

    def token_to_user(self, token):
        headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        
        data = {
            'grant_type': 'password',
            'client_id': self.client_config['web']['client_id'],
            'client_secret': self.client_config['web']['client_secret'],
            'username': self.client_config['web']['admin_username'],
            'password': self.client_config['web']['admin_password'],
            'token': token
        }

        url = self.client_config['web']['token_introspection_uri']
        print(url)
        
        response = requests.post(url, data=data)
        if response.status_code != requests.codes.ok:
            return response.status_code, response.json()

        data = response.json()
        return response.status_code, json.loads(json.dumps({"id": data['sub'],"email": data['email'], "roles": data['realm_access']['roles']}))

    def refresh_admin_token(self):
        print("new admin token")
        self.admin_access_token, self.admin_refresh_token = self.admin_token()

    def get_user_id(self, token):
        data = {
            'grant_type': 'password',
            'client_id': self.client_config['web']['client_id'],
            'client_secret': self.client_config['web']['client_secret'],
            'username': self.client_config['web']['admin_username'],
            'password': self.client_config['web']['admin_password'],
            'token': token
        }
        url = self.client_config['web']['token_introspection_uri']
        response = requests.post(url, data=data)

        return response.status_code, response.json()
    
    def is_token_valid(self, token):
        data = {
            'grant_type': 'password',
            'client_id': self.client_config['web']['client_id'],
            'client_secret': self.client_config['web']['client_secret'],
            'username': self.client_config['web']['admin_username'],
            'password': self.client_config['web']['admin_password'],
            'token': token
        }
        url = self.client_config['web']['token_introspection_uri']
        response = requests.post(url, data=data)

        if response.status_code != requests.codes.ok:
            return False
        
        data = response.json()
        if 'sub' in data.keys():
            # token still valid
            return True
        else:
            # token has expired
            return False

    """ Requests token for a specific user
        - @return:
            - code: http code returned by keycloak 
            - json object: token information or error from keycloak
    """
    def get_auth_token(self, username, password):
        data = {
            'grant_type': 'password',
            'client_id': self.client_config['web']['client_id'],
            'client_secret': self.client_config['web']['client_secret'],
            'username': username,
            'password': password
        }
        token_response = requests.post(self.client_config['web']['token_uri'], data=data)

        if token_response.status_code != requests.codes.ok:
            return token_response.status_code, token_response.json()
        
        tokens_data = token_response.json()
        
        access_data = {'username': username, "access_token": tokens_data['access_token'], "refresh_token": tokens_data['refresh_token']}
        return token_response.status_code, json.loads(json.dumps(access_data))

    """ Requests new access token using refresh token
        - @return:
            - code: http code returned by keycloak
            - json object: token information or error from keycloak    
    """
    def refresh_token(self, refresh_token):
        data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_config['web']['client_id'],
            'client_secret': self.client_config['web']['client_secret'],
            'refresh_token': refresh_token,
        }
        token_response = requests.post(self.client_config['web']['token_uri'], data=data)

        if token_response.status_code != requests.codes.ok:
            return token_response.status_code, token_response.json()
        
        tokens_data = token_response.json()

        tokens = {"access_token": tokens_data['access_token'], "refresh_token": tokens_data['refresh_token']}
        return token_response.status_code, jsonify(tokens)

    """ Method to close user session at keycloak
        @params:
            - user_id: user identifier
    """
    def logout(self, user_id):
        # Check if admin token is still valid
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + '/' + user_id + '/logout'
        response = requests.post(url, headers=headers)

        if response.status_code == 204:
            return response.status_code, jsonify({"details": "Correctly logged out"})
            
        return response.status_code, response.json()

    """ Method to create a new user inside keycloak
        @params: user information to create a new user
        @return:
            - status_code: status of the HTTP request
            - msg: response data
    """
    def create_user(self, email, username, firstName, lastName, password):
        # Check if admin token is still valid
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        data = {"email": email, "username": username, "firstName": firstName, "lastName": lastName,
            "credentials": [{"value": password, "type": 'password', 'temporary': False}],
            "enabled": True,
            "emailVerified": True
        }

        response = requests.post(self.client_config['web']['admin_users_uri'], headers=headers, json=data)

        return response.status_code, response.json()