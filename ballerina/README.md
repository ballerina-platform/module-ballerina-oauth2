## Overview

This module provides a framework for interacting with OAuth2 authorization servers as specified in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) and [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662), enabling third-party applications to obtain limited access to HTTP services, and defines auth providers for clients and listeners of different protocol connectors.

## Key Features

- Listener and Client OAuth2 providers
- Token introspection support, per RFC 7662

### Listener OAuth2 provider

Represents the listener OAuth2 provider, which is used to validate the received credential (access token) by calling the configured OAuth2 introspection endpoint.

### Client OAuth2 provider

Represents the client OAuth2 provider, which is used to generate OAuth2 access tokens using the configured OAuth2 token endpoint configurations. This supports the client credentials grant type, password grant type, and refresh token grant type.
