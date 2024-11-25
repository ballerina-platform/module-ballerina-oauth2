## Overview

This module provides a framework for interacting with OAuth2 authorization servers as specified in the [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) and [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662).

The OAuth 2.0 authorization framework enables a third-party application to obtain limited access to an HTTP service either on behalf of a resource owner by orchestrating an approval interaction between the resource owner and the HTTP service or by allowing the third-party application to obtain access on its own behalf.

The Ballerina `oauth2` module facilitates auth providers that are to be used by the clients and listeners of different protocol connectors.

### Listener OAuth2 provider

Represents the listener OAuth2 provider, which is used to validate the received credential (access token) by calling the configured OAuth2 introspection endpoint.

### Client OAuth2 provider

Represents the client OAuth2 provider, which is used to generate OAuth2 access tokens using the configured OAuth2 token endpoint configurations. This supports the client credentials grant type, password grant type, and refresh token grant type.
