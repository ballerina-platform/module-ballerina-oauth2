// Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/auth;
import ballerina/encoding;
import ballerina/http;
import ballerina/log;
import ballerina/mime;
import ballerina/runtime;
import ballerina/time;

# Represents outbound OAuth2 provider.
#
# + oauth2ProviderConfig - Outbound OAuth2 provider configurations
# + tokenCache - Cached token configurations
public type OutboundOAuth2Provider object {

    *auth:OutboundAuthProvider;

    public OAuth2ProviderConfig oauth2ProviderConfig;
    public CachedToken tokenCache;

    # Provides authentication based on the provided OAuth2 configuration.
    #
    # + outboundJwtAuthConfig - Outbound OAuth2 authentication configurations
    public function __init(OAuth2ProviderConfig oauth2ProviderConfig) {
        self.oauth2ProviderConfig = oauth2ProviderConfig;
        self.tokenCache = {
            accessToken: "",
            refreshToken: "",
            expiryTime: 0
        };
    }

    # Generate token for OAuth2 authentication.
    #
    # + return - Generated token or `error` if an error occurred
    public function generateToken() returns string|error {
        return check getAuthTokenForOAuth2(self.oauth2ProviderConfig, self.tokenCache, false);
    }

    # Inspect the incoming data and generate the token for OAuth2 authentication.
    #
    # + data - Map of data which is extracted from the HTTP response
    # + return - String token, or `error` occurred when generating token or `()` if nothing to be returned
    public function inspect(map<anydata> data) returns string|error? {
        if (data[http:STATUS_CODE] == http:UNAUTHORIZED_401) {
            var config = self.oauth2ProviderConfig.config;
            if (config is ClientCredentialsGrantConfig) {
                if (config.retryRequest) {
                    return check getAuthTokenForOAuth2(self.oauth2ProviderConfig, self.tokenCache, true);
                }
            } else if (config is PasswordGrantConfig) {
                if (config.retryRequest) {
                    return check getAuthTokenForOAuth2(self.oauth2ProviderConfig, self.tokenCache, true);
                }
            } else {
                if (config.retryRequest) {
                    config.accessToken = EMPTY_STRING;
                    return check getAuthTokenForOAuth2(self.oauth2ProviderConfig, self.tokenCache, true);
                }
            }
        }
        return ();
    }
};

# The `OAuth2ProviderConfig` record can be used to configure OAuth2 based authentication used by the HTTP endpoint.
#
# + grantType - OAuth2 grant type
# + config - Configurations for the given grant type
public type OAuth2ProviderConfig record {|
    OAuth2GrantType grantType;
    ClientCredentialsGrantConfig|PasswordGrantConfig|DirectTokenConfig config;
|};

# The `ClientCredentialsGrantConfig` record can be used to configue OAuth2 client credentials grant type.
#
# + tokenUrl - Token URL for the authorization endpoint
# + clientId - Client ID for the client credentials grant authentication
# + clientSecret - Client secret for the client credentials grant authentication
# + scopes - Scope of the access request
# + clockSkew - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
# + clientConfig - HTTP client configurations which calls the authorization endpoint
public type ClientCredentialsGrantConfig record {|
    string tokenUrl;
    string clientId;
    string clientSecret;
    string[] scopes?;
    int clockSkew = 0;
    boolean retryRequest = true;
    http:CredentialBearer credentialBearer = http:AUTH_HEADER_BEARER;
    http:ClientEndpointConfig clientConfig = {};
|};

# The `PasswordGrantConfig` record can be used to configue OAuth2 password grant type
#
# + tokenUrl - Token URL for the authorization endpoint
# + username - Username for password grant authentication
# + password - Password for password grant authentication
# + clientId - Client ID for password grant authentication
# + clientSecret - Client secret for password grant authentication
# + scopes - Scope of the access request
# + refreshConfig - Configurations for refreshing the access token
# + clockSkew - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
# + clientConfig - HTTP client configurations which calls the authorization endpoint
public type PasswordGrantConfig record {|
    string tokenUrl;
    string username;
    string password;
    string clientId?;
    string clientSecret?;
    string[] scopes?;
    RefreshConfig refreshConfig?;
    int clockSkew = 0;
    boolean retryRequest = true;
    http:CredentialBearer credentialBearer = http:AUTH_HEADER_BEARER;
    http:ClientEndpointConfig clientConfig = {};
|};

# The `DirectTokenConfig` record configures the access token directly.
#
# + accessToken - Access token for the authorization endpoint
# + refreshConfig - Configurations for refreshing the access token
# + clockSkew - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
public type DirectTokenConfig record {|
    string accessToken?;
    DirectTokenRefreshConfig refreshConfig?;
    int clockSkew = 0;
    boolean retryRequest = true;
    http:CredentialBearer credentialBearer = http:AUTH_HEADER_BEARER;
|};

# The `RefreshConfig` record can be used to pass the configurations for refreshing the access token of password grant type.
#
# + refreshUrl - Refresh token URL for the refresh token server
# + scopes - Scope of the access request
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
# + clientConfig - HTTP client configurations which calls the authorization endpoint
public type RefreshConfig record {|
    string refreshUrl;
    string[] scopes?;
    http:CredentialBearer credentialBearer = http:AUTH_HEADER_BEARER;
    http:ClientEndpointConfig clientConfig = {};
|};

# The `DirectTokenRefreshConfig` record passes the configurations for refreshing the access token for
# the grant type of the direct token grant type.
#
# + refreshUrl - Refresh token URL for the refresh token server
# + refreshToken - Refresh token for the refresh token server
# + clientId - Client ID for authentication with the authorization endpoint
# + clientSecret - Client secret for authentication with the authorization endpoint
# + scopes - Scope of the access request
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
# + clientConfig - HTTP client configurations which calls the authorization endpoint
public type DirectTokenRefreshConfig record {|
    string refreshUrl;
    string refreshToken;
    string clientId;
    string clientSecret;
    string[] scopes?;
    http:CredentialBearer credentialBearer = http:AUTH_HEADER_BEARER;
    http:ClientEndpointConfig clientConfig = {};
|};

# The `CachedToken` stores the values received from the authorization/token server to use them
# for the latter requests without requesting tokens again.
#
# + accessToken - Access token for the  authorization endpoint
# + refreshToken - Refresh token for the refresh token server
# + expiryTime - Expiry time of the access token in milliseconds
public type CachedToken record {
    string accessToken;
    string refreshToken;
    int expiryTime;
};

# The `RequestConfig` record prepares the HTTP request, which is to be sent to the authorization endpoint.
#
# + payload - Payload of the request
# + clientId - Client ID for client credentials grant authentication
# + clientSecret - Client secret for client credentials grant authentication
# + scopes - Scope of the access request
# + credentialBearer - How authentication credentials are sent to the authorization endpoint
type RequestConfig record {|
    string payload;
    string clientId?;
    string clientSecret?;
    string[]? scopes;
    http:CredentialBearer credentialBearer;
|};

# Process auth token for OAuth2.
#
# + authConfig - OAuth2 configurations
# + tokenCache - Cached token configurations
# + updateRequest - Check if the request is updated after a 401 response
# + return - Auth token or `error` if the validation fails
function getAuthTokenForOAuth2(OAuth2ProviderConfig authConfig, CachedToken tokenCache,
                               boolean updateRequest) returns string|error {
    var grantType = authConfig.grantType;
    var grantTypeConfig = authConfig.config;
    if (grantType is PASSWORD_GRANT) {
        if (grantTypeConfig is PasswordGrantConfig) {
            return getAuthTokenForOAuth2PasswordGrant(grantTypeConfig, tokenCache);
        } else {
            return prepareError("Invalid config is provided for the password grant type.");
        }
    } else if (grantType is CLIENT_CREDENTIALS_GRANT) {
        if (grantTypeConfig is ClientCredentialsGrantConfig) {
            return getAuthTokenForOAuth2ClientCredentialsGrant(grantTypeConfig, tokenCache);
        } else {
            return prepareError("Invalid config is provided for the password grant type.");
        }
    } else {
        // Within this code block, the grant type is DIRECT_TOKEN
        if (grantTypeConfig is DirectTokenConfig) {
            if (updateRequest) {
                grantTypeConfig.accessToken = EMPTY_STRING;
            }
            return getAuthTokenForOAuth2DirectTokenMode(grantTypeConfig, tokenCache);
        } else {
            return prepareError("Invalid config is provided for the direct token mode.");
        }
    }
}

# Process the auth token for OAuth2 password grant.
#
# + grantTypeConfig - Password grant configurations
# + tokenCache - Cached token configurations
# + return - Auth token or `error` if an error occurred during the HTTP client invocation or validation
function getAuthTokenForOAuth2PasswordGrant(PasswordGrantConfig grantTypeConfig,
                                            CachedToken tokenCache) returns string|error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == EMPTY_STRING) {
        string accessToken = check getAccessTokenFromAuthorizationRequest(grantTypeConfig, tokenCache);
        log:printDebug(function () returns string {
            return "OAuth2 password grant type; Access token received from authorization request. Cache is empty.";
        });
        return accessToken;
    } else {
        if (isCachedTokenValid(tokenCache)) {
            log:printDebug(function () returns string {
                return "OAuth2 password grant type; Access token received from cache.";
            });
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache)) {
                    cachedAccessToken = tokenCache.accessToken;
                    log:printDebug(function () returns string {
                        return "OAuth2 password grant type; Access token received from cache.";
                    });
                    return cachedAccessToken;
                } else {
                    string accessToken = check getAccessTokenFromRefreshRequest(grantTypeConfig, tokenCache);
                    log:printDebug(function () returns string {
                        return "OAuth2 password grant type; Access token received from refresh request.";
                    });
                    return accessToken;
                }
            }
        }
    }
}

# Process the auth token for OAuth2 client credentials grant.
#
# + grantTypeConfig - Client credentials grant configurations
# + tokenCache - Cached token configurations
# + return - Auth token or `error` if an error occurred during the HTTP client invocation or validation
function getAuthTokenForOAuth2ClientCredentialsGrant(ClientCredentialsGrantConfig grantTypeConfig,
                                                     CachedToken tokenCache) returns string|error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == EMPTY_STRING) {
        string accessToken = check getAccessTokenFromAuthorizationRequest(grantTypeConfig, tokenCache);
        log:printDebug(function () returns string {
            return "OAuth2 client credentials grant type; Access token received from authorization request.
                Cache is empty.";
        });
        return accessToken;
    } else {
        if (isCachedTokenValid(tokenCache)) {
            log:printDebug(function () returns string {
                return "OAuth2 client credentials grant type; Access token received from cache.";
            });
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache)) {
                    cachedAccessToken = tokenCache.accessToken;
                    log:printDebug(function () returns string {
                        return "OAuth2 client credentials grant type; Access token received from cache.";
                    });
                    return cachedAccessToken;
                } else {
                    string accessToken = check getAccessTokenFromAuthorizationRequest(grantTypeConfig, tokenCache);
                    log:printDebug(function () returns string {
                        return "OAuth2 client credentials grant type; Access token received from authorization request.";
                    });
                    return accessToken;
                }
            }
        }
    }
}

# Process the auth token for OAuth2 direct token mode.
#
# + grantTypeConfig - Direct token configurations
# + tokenCache - Cached token configurations
# + return - Auth token or `error` if an error occurred during the HTTP client invocation or validation
function getAuthTokenForOAuth2DirectTokenMode(DirectTokenConfig grantTypeConfig,
                                              CachedToken tokenCache) returns string|error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == EMPTY_STRING) {
        var directAccessToken = grantTypeConfig["accessToken"];
        if (directAccessToken is string && directAccessToken != EMPTY_STRING) {
            log:printDebug(function () returns string {
                return "OAuth2 direct token mode; Access token received from user given request. Cache is empty.";
            });
            return directAccessToken;
        } else {
            string accessToken = check getAccessTokenFromRefreshRequest(grantTypeConfig, tokenCache);
            log:printDebug(function () returns string {
                return "OAuth2 direct token mode; Access token received from refresh request. Cache is empty.";
            });
            return accessToken;
        }
    } else {
        if (isCachedTokenValid(tokenCache)) {
            log:printDebug(function () returns string {
                return "OAuth2 client credentials grant type; Access token received from cache.";
            });
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache)) {
                    cachedAccessToken = tokenCache.accessToken;
                    log:printDebug(function () returns string {
                        return "OAuth2 client credentials grant type; Access token received from cache.";
                    });
                    return cachedAccessToken;
                } else {
                    string accessToken = check getAccessTokenFromRefreshRequest(grantTypeConfig, tokenCache);
                    log:printDebug(function () returns string {
                        return "OAuth2 direct token mode; Access token received from refresh request.";
                    });
                    return accessToken;
                }
            }
        }
    }
}

# Check the validity of the access toke,n which is in the cache. If the expiry time is 0, that means no expiry time is
# returned with the authorization request. This implies that the token is valid forever.
#
# + tokenCache - Cached token configurations
# + return - Whether the access token is valid or not
function isCachedTokenValid(CachedToken tokenCache) returns boolean {
    int expiryTime = tokenCache.expiryTime;
    if (expiryTime == 0) {
        log:printDebug(function () returns string {
            return "Expiry time is 0, which means cached access token is always valid until we get a 401 response.";
        });
        return true;
    }
    int currentSystemTime = time:currentTime().time;
    if (currentSystemTime > expiryTime) {
        log:printDebug(function () returns string {
            return "Current time > expiry time, which means cached access token is valid until we get a 401 response.";
        });
        return true;
    }
    log:printDebug(function () returns string {
        return "Cached access token is invalid.";
    });
    return false;
}

# Request an access token from the authorization endpoint using the provided configurations.
#
# + config - Grant type configuration
# + tokenCache - Cached token configurations
# + return - Access token received or `error` if an error occurred during the HTTP client invocation
function getAccessTokenFromAuthorizationRequest(ClientCredentialsGrantConfig|PasswordGrantConfig config,
                                                CachedToken tokenCache) returns string|error {
    RequestConfig requestConfig;
    int clockSkew;
    string tokenUrl;
    http:ClientEndpointConfig clientConfig;

    if (config is ClientCredentialsGrantConfig) {
        if (config.clientId == EMPTY_STRING || config.clientSecret == EMPTY_STRING) {
            return prepareError("Client id or client secret cannot be empty.");
        }
        tokenUrl = config.tokenUrl;
        requestConfig = {
            payload: "grant_type=client_credentials",
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            scopes: config["scopes"],
            credentialBearer: config.credentialBearer
        };
        clockSkew = config.clockSkew;
        clientConfig = config.clientConfig;
    } else {
        tokenUrl = config.tokenUrl;
        var clientId = config["clientId"];
        var clientSecret = config["clientSecret"];
        if (clientId is string && clientSecret is string) {
            if (clientId == EMPTY_STRING || clientSecret == EMPTY_STRING) {
                return prepareError("Client id or client secret cannot be empty.");
            }
            requestConfig = {
                payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
                clientId: clientId,
                clientSecret: clientSecret,
                scopes: config["scopes"],
                credentialBearer: config.credentialBearer
            };
        } else {
            requestConfig = {
                payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
                scopes: config["scopes"],
                credentialBearer: config.credentialBearer
            };
        }
        clockSkew = config.clockSkew;
        clientConfig = config.clientConfig;
    }

    http:Request authorizationRequest = check prepareRequest(requestConfig);
    return doRequest(tokenUrl, authorizationRequest, clientConfig, tokenCache, clockSkew);
}

# Request an access token from the authorization endpoint using the provided refresh configurations.
#
# + config - Password grant type configuration or direct token configuration
# + tokenCache - Cached token configurations
# + return - Access token received or `error` if an error occurred during HTTP client invocation
function getAccessTokenFromRefreshRequest(PasswordGrantConfig|DirectTokenConfig config,
                                          CachedToken tokenCache) returns string|error {
    RequestConfig requestConfig;
    int clockSkew;
    string refreshUrl;
    http:ClientEndpointConfig clientConfig;

    if (config is PasswordGrantConfig) {
        var refreshConfig = config["refreshConfig"];
        if (refreshConfig is RefreshConfig) {
            if (config.clientId == EMPTY_STRING || config.clientSecret == EMPTY_STRING) {
                return prepareError("Client id or client secret cannot be empty.");
            }
            refreshUrl = untaint refreshConfig.refreshUrl;
            requestConfig = {
                payload: "grant_type=refresh_token&refresh_token=" + tokenCache.refreshToken,
                clientId: config.clientId,
                clientSecret: config.clientSecret,
                scopes: refreshConfig["scopes"],
                credentialBearer: refreshConfig.credentialBearer
            };
            clientConfig = refreshConfig.clientConfig;
        } else {
            return prepareError("Failed to refresh access token since RefreshTokenConfig is not provided.");
        }
        clockSkew = config.clockSkew;
    } else {
        var refreshConfig = config["refreshConfig"];
        if (refreshConfig is DirectTokenRefreshConfig) {
            if (refreshConfig.clientId == EMPTY_STRING || refreshConfig.clientSecret == EMPTY_STRING) {
                string errMsg = "Client id or client secret cannot be empty.";
                return prepareError(errMsg);
            }
            refreshUrl = refreshConfig.refreshUrl;
            requestConfig = {
                payload: "grant_type=refresh_token&refresh_token=" + refreshConfig.refreshToken,
                clientId: refreshConfig.clientId,
                clientSecret: refreshConfig.clientSecret,
                scopes: refreshConfig["scopes"],
                credentialBearer: refreshConfig.credentialBearer
            };
            clientConfig = refreshConfig.clientConfig;
        } else {
            return prepareError("Failed to refresh access token since DirectRefreshTokenConfig is not provided.");
        }
        clockSkew = config.clockSkew;
    }

    http:Request refreshRequest = check prepareRequest(requestConfig);
    return doRequest(refreshUrl, refreshRequest, clientConfig, tokenCache, clockSkew);
}

# Execute the actual request and get the access token from authorization endpoint.
#
# + url - URL of the authorization endpoint
# + request - Prepared request to be sent to the authorization endpoint
# + clientConfig - HTTP client configurations which calls the authorization endpoint
# + tokenCache - Cached token configurations
# + clockSkew - Clock skew in seconds
# + return - Access token received or `error` if an error occurred during HTTP client invocation
function doRequest(string url, http:Request request, http:ClientEndpointConfig clientConfig, CachedToken tokenCache,
                   int clockSkew) returns string|error {
    http:Client clientEP = new(url, config = clientConfig);
    var response = clientEP->post(EMPTY_STRING, request);
    if (response is http:Response) {
        log:printDebug(function () returns string {
            return "Request sent successfully to URL: " + url;
        });
        return extractAccessTokenFromResponse(response, tokenCache, clockSkew);
    } else {
        return prepareError("Failed to send request to URL: " + url, err = response);
    }
}

# Prepare the request to be sent to the authorization endpoint by adding the relevant headers and payloads.
#
# + config - `RequestConfig` record
# + return - Prepared HTTP request object
function prepareRequest(RequestConfig config) returns http:Request|error {
    http:Request req = new;
    string textPayload = config.payload;
    string scopeString = EMPTY_STRING;
    string[]? scopes = config.scopes;
    if (scopes is string[]) {
        foreach var requestScope in scopes {
            string trimmedRequestScope = requestScope.trim();
            if (trimmedRequestScope != EMPTY_STRING) {
                scopeString = scopeString + WHITE_SPACE + trimmedRequestScope;
            }
        }
    }
    if (scopeString != EMPTY_STRING) {
        textPayload = textPayload + "&scope=" + scopeString;
    }

    var clientId = config["clientId"];
    var clientSecret = config["clientSecret"];
    if (config.credentialBearer == http:AUTH_HEADER_BEARER) {
        if (clientId is string && clientSecret is string) {
            string clientIdSecret = clientId + ":" + clientSecret;
            req.addHeader(http:AUTH_HEADER, auth:AUTH_SCHEME_BASIC +
                    encoding:encodeBase64(clientIdSecret.toByteArray("UTF-8")));
        } else {
            return prepareError("Client ID or client secret is not provided for client authentication.");
        }
    } else if (config.credentialBearer == http:POST_BODY_BEARER) {
        if (clientId is string && clientSecret is string) {
            textPayload = textPayload + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        } else {
            return prepareError("Client ID or client secret is not provided for client authentication.");
        }
    }
    req.setTextPayload(untaint textPayload, contentType = mime:APPLICATION_FORM_URLENCODED);
    return req;
}

# Extract the access token from the JSON payload of a given HTTP response and update the token cache.
#
# + response - HTTP response object
# + tokenCache - Cached token configurations
# + clockSkew - Clock skew in seconds
# + return - Extracted access token or `error` if an error occurred during the HTTP client invocation
function extractAccessTokenFromResponse(http:Response response, CachedToken tokenCache, int clockSkew) returns string|error {
    if (response.statusCode == http:OK_200) {
        var payload = response.getJsonPayload();
        if (payload is json) {
            log:printDebug(function () returns string {
                return "Received an valid response. Extracting access token from the payload.";
            });
            check updateTokenCache(payload, tokenCache, clockSkew);
            return payload.access_token.toString();
        } else {
            return prepareError("Failed to retrieve access token since the response payload is not a JSON.", err = payload);
        }
    } else {
        var payload = response.getTextPayload();
        if (payload is string) {
            return prepareError("Received an invalid response. StatusCode: " + response.statusCode + " Payload: " + payload);
        } else {
            return prepareError("Received an invalid response. StatusCode: " + response.statusCode, err = payload);
        }
    }
}

# Update the token cache with the received JSON payload of the response.
#
# + responsePayload - Payload of the response
# + tokenCache - Cached token configurations
# + clockSkew - Clock skew in seconds
# + return - `error` if an error occurred during the conversion of the parameters
function updateTokenCache(json responsePayload, CachedToken tokenCache, int clockSkew) returns error? {
    int issueTime = time:currentTime().time;
    string accessToken = responsePayload.access_token.toString();
    tokenCache.accessToken = accessToken;
    var expiresIn = responsePayload["expires_in"];
    if (expiresIn is int) {
        tokenCache.expiryTime = issueTime + (expiresIn - clockSkew) * 1000;
    }
    if (responsePayload["refresh_token"] is string) {
        string refreshToken = responsePayload.refresh_token.toString();
        tokenCache.refreshToken = refreshToken;
    }
    log:printDebug(function () returns string {
        return "Updated token cache with the new parameters of the response.";
    });
    return ();
}
