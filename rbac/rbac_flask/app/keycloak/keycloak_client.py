import requests, os, json
from requests.auth import HTTPBasicAuth
from flask import ( jsonify )

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
        url = self.client_config['web']['admin_token_uri']

        response = requests.post(url, data=data)

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
        
        response = requests.post(url, data=data)
        if response.status_code != requests.codes.ok:
            return response.status_code, response.json()

        data = response.json()
        return response.status_code, json.loads(json.dumps({"id": data['sub'],"email": data['email'], "roles": data['realm_access']['roles']}))

    def refresh_admin_token(self):
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
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        url = self.client_config['web']['token_uri']
        token_response = requests.post(url, data=data)

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
        url = self.client_config['web']['token_uri']
        token_response = requests.post(url, data=data)

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

    ##################
    ### CRUD Users ###
    ##################
    """ Method to create a new user inside keycloak
        @params: user information to create a new user
        @return:
            - status_code: status of the HTTP request
            - msg: response data
    """
    def create_user(self, email, username, firstName, lastName, password, roles):
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
        
        url = self.client_config['web']['admin_users_uri']
        response = requests.post(url, headers=headers, json=data)

        if response.status_code in [200, 201]:
            url = self.client_config['web']['admin_users_uri']+"?email={}".format(email)
            resp_get_user_id = requests.get(url, headers=headers)

            users = resp_get_user_id.json()
            user_data = resp_get_user_id.json()[0]
            user = {"user_id": user_data['id']}

            # Add role to user at keycloak
            add_role_status_code, add_role_response = self.add_role_to_user(user_data['id'], roles)
            
            if add_role_status_code != 204:
                return add_role_status_code, jsonify({"details": "Error assigning role to user"})

            return response.status_code, user

        return response.status_code, response.json()

    """ Method to delete a user inside keycloak
        @params: user id
        @return:
            - status_code: status of the HTTP request
            - msg: response data
    """
    def delete_user(self, user_id):
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + '/' + user_id
        response = requests.delete(url, headers=headers)
        
        return response.status_code, jsonify({"info": "User {} removed".format(user_id)})

    """ Method to get user from keycloak
        @params: user id
        @return:
            - status_code: status of the HTTP request
            - msg: response data
    """
    def get_user(self, user_id):
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + '/' + user_id
        response = requests.get(url, headers=headers)
        
        return response.status_code, response.json()        

    def get_user_by_email(self, user_email):
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + '?email=' + user_email
        response = requests.get(url, headers=headers)
        
        return response.status_code, response.content


    """ Method to update the password of a user
        @params: user id
    """
    def change_password(self, user_id, new_password):
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        data = {
            "type": "password",
            "temporary": "false",
            "value": new_password
        }

        url = self.client_config['web']['admin_users_uri'] + '/' + user_id + '/reset-password'

        response = requests.put(url, headers=headers, json=data)

        return response.status_code, response.content

    #######################
    ### User Attributes ###
    #######################

    def get_user_attributes(self, user_id, attribute_name):
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + '/' + user_id
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            try:
                attributes = data['attributes'][attribute_name]
            except Exception as e:
                attributes = []
            return response.status_code, attributes

        return response.status_code, response.json()

    def add_user_attributes(self, user_id, attribute_name, data):

        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        status, user_data = self.get_user(user_id)
        if status == 200:

            url = self.client_config['web']['admin_users_uri'] + '/' + user_id

            try:
                attributes = user_data['attributes'][attribute_name]

            except KeyError as e:
                user_data['attributes'] = {}
                user_data['attributes'][attribute_name] = []
                attributes = []
          
            for attribute in data:
                if str(attribute) not in attributes:
                    user_data['attributes'][attribute_name].append(str(attribute))
                    attributes = user_data['attributes'][attribute_name]

            response = requests.put(url, headers=headers, json=user_data)
            
            if response.status_code == 204:
                return response.status_code, ""
        else:
            return response.status_code, response.json()

    def delete_user_attributes(self, user_id, attribute_name, values_tb_deleted):

        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        status, user_data = self.get_user(user_id)

        if status == 200:
            url = self.client_config['web']['admin_users_uri'] + '/' + user_id

            try:
                attributes = user_data['attributes'][attribute_name]
            except KeyError:
                attributes = []

            try:
                for value in values_tb_deleted:
                    if value in attributes:
                        user_data['attributes'][attribute_name].remove(value)

                response = requests.put(url, headers=headers, json=user_data)

                if response.status_code == 204:
                    return response.status_code, ""
                else:
                    return response.status_code, response.json()

            except Exception as e:
                return 204, ""
        else:
            return response.status_code, response.json()



    #############
    ### Roles ###
    #############
    """ Method to add roles to a specific user
        @params: 
            - user id
            - roles to be added (list of role names)
        @return:
            - status_code: status of the HTTP request
            - msg: response data
    """
    def add_role_to_user(self, user_id, roles):
        # Check if admin token is still valid
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        reply, data = self.get_realm_roles(user_id)

        # [{"id": "role_id", "name": "role_name", "clientRole": False}, {...}]
        assigned_roles = []
        for role in roles:
            for realm_role in data:
                if role == realm_role['name']:
                    assigned_roles.append(realm_role)

        url = self.client_config['web']['admin_users_uri'] + "/" + user_id + "/role-mappings/realm"
        response = requests.post(url, headers=headers, data=json.dumps(assigned_roles))

        if response.status_code == 204:
            return response.status_code, ""

        return response.status_code, response.json()

    def get_realm_roles(self, user_id):
        # Check if admin token is still valid
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}

        url = self.client_config['web']['admin_users_uri'] + "/" + user_id + "/role-mappings/realm/available"
        response = requests.get(url, headers=headers)

        return response.status_code, response.json()
    
    def get_available_roles(self):
        # Check if admin token is still valid
        if self.is_token_valid(self.admin_access_token):
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        else:
            self.refresh_admin_token()
            headers = {'Authorization': 'Bearer {}'.format(self.admin_access_token), 'Content-Type': 'application/json'}
        
        url = self.client_config['web']['admin_roles_uri']
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            realmroles = response.json()
            available_roles = []
            for element in realmroles:
                if element['name'] not in ['offline_access', 'uma_authorization', 'enabled', 'disabled']:
                    available_roles.append(element)

            return response.status_code, available_roles

        else:
            return response.status_code, response.json()
