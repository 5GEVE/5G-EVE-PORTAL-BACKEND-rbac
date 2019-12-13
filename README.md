  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# 5G-EVE Portal Components
This repository contains part of the back-end modules implementing the functionality provided by 5G-EVE portal. It contains modules for authentication/authorization relying on Keycloak and a ticketing system which basically relies on bugzilla.

# Packages included
## RBAC
Module implemented in python Flask that provides an interface to interact with Keycloak, hence providing a plain interface to users management, authentication and authorization.

## keycloak
Dockerized version of keycloak that allows RBAC to provide token-based authentication/authorization methanisms.

## Authors
Ginés García Avilés [Gitlab](https://gitlab.com/GinesGarcia) [Github](https://github.com/GinesGarcia) [website](https://www.it.uc3m.es/gigarcia/index.html)

## Acknowledgments
* [5G EVE](https://www.5g-eve.eu/)