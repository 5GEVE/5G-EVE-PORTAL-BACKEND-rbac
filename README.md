  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# 5G-EVE Portal Components
This repository contains part of the back-end modules implementing the functionality provided by 5G-EVE portal. It contains modules for authentication/authorization relying on Keycloak and a ticketing system which basically relies on bugzilla.

# Packages included
## RBAC
Module implemented in python Flask that provides an interface to interact with Keycloak, hence providing a plain interface to users management, authentication and authorization.

## keycloak
Dockerized version of keycloak that allows RBAC to provide token-based authentication/authorization methanisms.

# Required configuration
In order to allow RBAC module to interact with Keycloak, it is required to tell RBAC where keycloak will be listening. Moreover, we have to correctly configure keycloak in order to make RBAC a trusted service.

1. **RBAC**: Here we have to include the client credentials from keycloak in order to make it a trusted service together with the IP address where keycloak is listening. In order to do so, modify rbac_flask/keycloak.json as follows:
    - Replace http://ip_of_the_keycloak_container:8080 with the corresponding IP address
    - Fill client_id and client_secret with the parameters at the credentials tab inside the client details on keycloak
2. **Start Keycloak**: 
    - ```cd ./keycloak ```
    - ```docker-compose up```
3. **Keycloak configuration**:
    - Create a new Realm called "5geve"
    - Create a new client called RBAC with the following configuration:
        - Access type confidential
        - Valid redirect URIs *
    - Configure audience claims inside tokens [guide](https://stackoverflow.com/questions/53550321/keycloak-gatekeeper-aud-claim-and-client-id-do-not-match)
4. **Start RBAC service**:
    - ```cd ./rbac```
    - ```docker-compose up --build```
5. **Create new user**: Create a new user at Keycloak in order to login

## Examples
At exxamples_rbac_postman.json you can find simple examples of how to use the RBAC service via Postman.

## Authors
Ginés García Avilés [Gitlab](https://gitlab.com/GinesGarcia) [Github](https://github.com/GinesGarcia) [website](https://www.it.uc3m.es/gigarcia/index.html)

## Acknowledgments
* [5G EVE](https://www.5g-eve.eu/)