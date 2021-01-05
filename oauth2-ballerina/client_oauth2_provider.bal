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

import ballerina/time;

# The data structure, which is used to configure the OAuth2 client credentials grant type.
#
# + tokenUrl - Token URL for the authorization endpoint
# + clientId - Client ID for the client credentials grant authentication
# + clientSecret - Client secret for the client credentials grant authentication
# + scopes - Scope(s) of the access request
# + clockSkewInSeconds - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + parameters - Map of endpoint parameters use with the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type ClientCredentialsGrantConfig record {|
    string tokenUrl;
    string clientId;
    string clientSecret;
    string[] scopes?;
    int clockSkewInSeconds = 0;
    boolean retryRequest = true;
    map<string> parameters?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# The data structure, which is used to configure the OAuth2 password grant type.
#
# + tokenUrl - Token URL for the authorization endpoint
# + username - Username for the password grant authentication
# + password - Password for the password grant authentication
# + clientId - Client ID for the password grant authentication
# + clientSecret - Client secret for the password grant authentication
# + scopes - Scope(s) of the access request
# + refreshConfig - Configurations for refreshing the access token
# + clockSkewInSeconds - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + parameters - Map of endpoint parameters use with the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type PasswordGrantConfig record {|
    string tokenUrl;
    string username;
    string password;
    string clientId?;
    string clientSecret?;
    string[] scopes?;
    RefreshConfig refreshConfig?;
    int clockSkewInSeconds = 0;
    boolean retryRequest = true;
    map<string> parameters?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# The data structure, which is used to configure the OAuth2 access token directly.
#
# + accessToken - Access token for the authorization endpoint
# + refreshConfig - Configurations for refreshing the access token
# + clockSkewInSeconds - Clock skew in seconds
# + retryRequest - Retry the request if the initial request returns a 401 response
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
public type DirectTokenConfig record {|
    string accessToken?;
    DirectTokenRefreshConfig refreshConfig?;
    int clockSkewInSeconds = 0;
    boolean retryRequest = true;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
|};

# The data structure, which can be used to pass the configurations for refreshing the access token of
# the password grant type.
#
# + refreshUrl - Refresh token URL for the refresh token server
# + scopes - Scope(s) of the access request
# + parameters - Map of endpoint parameters use with the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type RefreshConfig record {|
    string refreshUrl;
    string[] scopes?;
    map<string> parameters?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# The data structure, which can be used to pass the configurations for refreshing the access token directly.
#
# + refreshUrl - Refresh token URL for the refresh token server
# + refreshToken - Refresh token for the refresh token server
# + clientId - Client ID for authentication with the authorization endpoint
# + clientSecret - Client secret for authentication with the authorization endpoint
# + scopes - Scope(s) of the access request
# + parameters - Map of endpoint parameters use with the authorization endpoint
# + credentialBearer - Bearer of authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type DirectTokenRefreshConfig record {|
    string refreshUrl;
    string refreshToken;
    string clientId;
    string clientSecret;
    string[] scopes?;
    map<string> parameters?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# The data structure, which stores the values received from the authorization/token server to use them
# for the latter requests without requesting tokens again.
#
# + accessToken - Access token received from the authorization endpoint
# + refreshToken - Refresh token for the refresh token server
# + expTime - Expiry time (milliseconds since the Epoch) of the access token
public type OutboundOAuth2CacheEntry record {
    string accessToken;
    string refreshToken;
    int expTime;
};

// The data structure, which stores the values needed to prepare the HTTP request, which are to be sent to the
// authorization endpoint.
type RequestConfig record {|
    string payload;
    string clientId?;
    string clientSecret?;
    string[]? scopes;
    map<string>? parameters;
    CredentialBearer credentialBearer;
|};

# Represents the grant type configs supported for OAuth2.
public type GrantConfig ClientCredentialsGrantConfig|PasswordGrantConfig|DirectTokenConfig;

# Represents the client OAuth2 provider, which generates OAtuh2 tokens. This supports the client credentials grant type,
# password grant type, and the direct token mode, which sends the access token directly.
#
# 1. Client Credentials Grant Type
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     tokenUrl: "https://localhost:9196/oauth2/token",
#     clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#     clientSecret: "9205371918321623741",
#     scopes: ["token-scope1", "token-scope2"]
# });
# ```
#
# 2. Password Grant Type
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     tokenUrl: "https://localhost:9196/oauth2/token/authorize/header",
#     username: "johndoe",
#     password: "A3ddj3w",
#     clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#     clientSecret: "9205371918321623741",
#     scopes: ["token-scope1", "token-scope2"]
# });
# ```
#
# 3. Direct Token Mode
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     accessToken: "2YotnFZFEjr1zCsicMWpAA",
#     refreshConfig: {
#         refreshUrl: "https://localhost:9196/oauth2/token/refresh",
#         refreshToken: "XlfBs91yquexJqDaKEMzVg==",
#         clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#         clientSecret: "9205371918321623741",
#         scopes: ["token-scope1", "token-scope2"]
#     }
# });
# ```
public class ClientOAuth2Provider {

    GrantConfig grantConfig;
    OutboundOAuth2CacheEntry oauth2CacheEntry;

    # Provides authentication based on the provided OAuth2 configurations.
    #
    # + grantConfig - OAuth2 grant type configurations
    public isolated function init(GrantConfig grantConfig) {
        self.grantConfig = grantConfig;
        self.oauth2CacheEntry = {
            accessToken: "",
            refreshToken: "",
            expTime: 0
        };
    }

    # Generate a token for the OAuth2 authentication.
    # ```ballerina
    # string:oauth2:Error token = provider.generateToken();
    # ```
    #
    # + return - Generated `string` token or else an `oauth2:Error` if an error occurred
    public isolated function generateToken() returns string|Error {
        string|Error authToken = generateOAuth2Token(self.grantConfig, self.oauth2CacheEntry);
        if (authToken is Error) {
            return prepareError("Failed to generate OAuth2 token.", authToken);
        }
        return <string>authToken;
    }
}

// Generates the OAuth2 token.
isolated function generateOAuth2Token(GrantConfig grantConfig, OutboundOAuth2CacheEntry oauth2CacheEntry)
                                      returns string|Error {
    if (grantConfig is PasswordGrantConfig) {
        return getOAuth2TokenForPasswordGrant(grantConfig, oauth2CacheEntry);
    } else if (grantConfig is ClientCredentialsGrantConfig) {
        return getOAuth2TokenForClientCredentialsGrant(grantConfig, oauth2CacheEntry);
    } else {
        return getOAuth2TokenForDirectTokenMode(grantConfig, oauth2CacheEntry);
    }
}

// Processes the OAuth2 token for the password grant type.
isolated function getOAuth2TokenForPasswordGrant(PasswordGrantConfig grantConfig,
                                                 OutboundOAuth2CacheEntry oauth2CacheEntry) returns string|Error {
    string cachedAccessToken = oauth2CacheEntry.accessToken;
    if (cachedAccessToken == "") {
        return getAccessTokenFromAuthorizationRequest(grantConfig, oauth2CacheEntry);
    } else {
        if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
                    return oauth2CacheEntry.accessToken;
                } else {
                    return getAccessTokenFromRefreshRequest(grantConfig, oauth2CacheEntry);
                }
            }
        }
    }
}

// Processes the OAuth2 token for the client credentials grant type.
isolated function getOAuth2TokenForClientCredentialsGrant(ClientCredentialsGrantConfig grantConfig,
                                                          OutboundOAuth2CacheEntry oauth2CacheEntry)
                                                          returns string|Error {
    string cachedAccessToken = oauth2CacheEntry.accessToken;
    if (cachedAccessToken == "") {
        return getAccessTokenFromAuthorizationRequest(grantConfig, oauth2CacheEntry);
    } else {
        if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
                    cachedAccessToken = oauth2CacheEntry.accessToken;
                    return cachedAccessToken;
                } else {
                    return getAccessTokenFromAuthorizationRequest(grantConfig, oauth2CacheEntry);
                }
            }
        }
    }
}

// Processes the OAuth2 token for the direct token mode.
isolated function getOAuth2TokenForDirectTokenMode(DirectTokenConfig grantConfig,
                                                   OutboundOAuth2CacheEntry oauth2CacheEntry) returns string|Error {
    string cachedAccessToken = oauth2CacheEntry.accessToken;
    if (cachedAccessToken == "") {
        string? directAccessToken = grantConfig?.accessToken;
        if (directAccessToken is string && directAccessToken != "") {
            return directAccessToken;
        } else {
            return getAccessTokenFromRefreshRequest(grantConfig, oauth2CacheEntry);
        }
    } else {
        if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isOAuth2CacheEntryValid(oauth2CacheEntry)) {
                    cachedAccessToken = oauth2CacheEntry.accessToken;
                    return cachedAccessToken;
                } else {
                    return getAccessTokenFromRefreshRequest(grantConfig, oauth2CacheEntry);
                }
            }
        }
    }
}

// Checks the validity of the access token, which is in the cache. If the expiry time is 0, that means no expiry time is
// returned with the authorization request. This implies that the token is valid forever.
isolated function isOAuth2CacheEntryValid(OutboundOAuth2CacheEntry oauth2CacheEntry) returns boolean {
    int expTime = oauth2CacheEntry.expTime;
    if (expTime == 0) {
        return true;
    }
    int currentSystemTime = time:currentTime().time;
    if (currentSystemTime < expTime) {
        return true;
    }
    return false;
}

// Requests an access token from the authorization endpoint using the provided configurations.
isolated function getAccessTokenFromAuthorizationRequest(ClientCredentialsGrantConfig|PasswordGrantConfig config,
                                                         OutboundOAuth2CacheEntry oauth2CacheEntry) returns string|Error {
    RequestConfig requestConfig;
    int clockSkewInSeconds;
    string tokenUrl;
    ClientConfiguration clientConfig;

    if (config is ClientCredentialsGrantConfig) {
        if (config.clientId == "" || config.clientSecret == "") {
            return prepareError("Client id or client secret cannot be empty.");
        }
        tokenUrl = config.tokenUrl;
        requestConfig = {
            payload: "grant_type=client_credentials",
            clientId: config.clientId,
            clientSecret: config.clientSecret,
            scopes: config?.scopes,
            parameters: config?.parameters,
            credentialBearer: config.credentialBearer
        };
        clockSkewInSeconds = config.clockSkewInSeconds;
        clientConfig = config.clientConfig;
    } else {
        tokenUrl = config.tokenUrl;
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            if (clientId == "" || clientSecret == "") {
                return prepareError("Client id or client secret cannot be empty.");
            }
            requestConfig = {
                payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
                clientId: clientId,
                clientSecret: clientSecret,
                scopes: config?.scopes,
                parameters: config?.parameters,
                credentialBearer: config.credentialBearer
            };
        } else {
            requestConfig = {
                payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
                scopes: config?.scopes,
                parameters: config?.parameters,
                credentialBearer: config.credentialBearer
            };
        }
        clockSkewInSeconds = config.clockSkewInSeconds;
        clientConfig = config.clientConfig;
    }
    return sendRequest(requestConfig, tokenUrl, clientConfig, oauth2CacheEntry, clockSkewInSeconds);
}

// Requests an access token from the authorization endpoint using the provided refresh configurations.
isolated function getAccessTokenFromRefreshRequest(PasswordGrantConfig|DirectTokenConfig config,
                                                   OutboundOAuth2CacheEntry oauth2CacheEntry) returns string|Error {
    RequestConfig requestConfig;
    int clockSkewInSeconds;
    string refreshUrl;
    ClientConfiguration clientConfig;

    if (config is PasswordGrantConfig) {
        RefreshConfig? refreshConfig = config?.refreshConfig;
        if (refreshConfig is RefreshConfig) {
            string? clientId = config?.clientId;
            string? clientSecret = config?.clientSecret;
            if (clientId is string && clientSecret is string) {
                if (clientId == "" || clientSecret == "") {
                    return prepareError("Client id or client secret cannot be empty.");
                }
                refreshUrl = refreshConfig.refreshUrl;
                requestConfig = {
                    payload: "grant_type=refresh_token&refresh_token=" + oauth2CacheEntry.refreshToken,
                    clientId: clientId,
                    clientSecret: clientSecret,
                    scopes: refreshConfig?.scopes,
                    parameters: refreshConfig?.parameters,
                    credentialBearer: refreshConfig.credentialBearer
                };
                clientConfig = refreshConfig.clientConfig;
            } else {
                return prepareError("Client id or client secret cannot be empty.");
            }
        } else {
            return prepareError("Failed to refresh access token since RefreshTokenConfig is not provided.");
        }
        clockSkewInSeconds = config.clockSkewInSeconds;
    } else {
        DirectTokenRefreshConfig? refreshConfig = config?.refreshConfig;
        if (refreshConfig is DirectTokenRefreshConfig) {
            if (refreshConfig.clientId == "" || refreshConfig.clientSecret == "") {
                return prepareError("Client id or client secret cannot be empty.");
            }
            refreshUrl = refreshConfig.refreshUrl;
            requestConfig = {
                payload: "grant_type=refresh_token&refresh_token=" + refreshConfig.refreshToken,
                clientId: refreshConfig.clientId,
                clientSecret: refreshConfig.clientSecret,
                scopes: refreshConfig?.scopes,
                parameters: refreshConfig?.parameters,
                credentialBearer: refreshConfig.credentialBearer
            };
            clientConfig = refreshConfig.clientConfig;
        } else {
            return prepareError("Failed to refresh access token since DirectRefreshTokenConfig is not provided.");
        }
        clockSkewInSeconds = config.clockSkewInSeconds;
    }
    return sendRequest(requestConfig, refreshUrl, clientConfig, oauth2CacheEntry, clockSkewInSeconds);
}

isolated function sendRequest(RequestConfig requestConfig, string url, ClientConfiguration clientConfig,
                              OutboundOAuth2CacheEntry oauth2CacheEntry, int clockSkewInSeconds) returns string|Error {
    map<string> headers = check prepareHeaders(requestConfig);
    string payload = check preparePayload(requestConfig);
    string|Error stringResponse = doHttpRequest(url, clientConfig, headers, payload);
    if (stringResponse is Error) {
        return prepareError("Failed to call introspection endpoint.", stringResponse);
    }
    return extractAccessToken(<string>stringResponse, oauth2CacheEntry, clockSkewInSeconds);
}

isolated function prepareHeaders(RequestConfig config) returns map<string>|Error {
    map<string> headers = {};
    if (config.credentialBearer == AUTH_HEADER_BEARER) {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            string clientIdSecret = clientId + ":" + clientSecret;
            headers["Authorization"] = "Basic " + clientIdSecret.toBytes().toBase64();
        } else {
            return prepareError("Client ID or client secret is not provided for client authentication.");
        }
    }
    return headers;
}

isolated function preparePayload(RequestConfig config) returns string|Error {
    string textPayload = config.payload;
    string scopeString = "";
    string[]? scopes = config.scopes;
    if (scopes is string[]) {
        foreach string requestScope in scopes {
            string trimmedRequestScope = requestScope.trim();
            if (trimmedRequestScope != "") {
                scopeString = scopeString + " " + trimmedRequestScope;
            }
        }
    }
    if (scopeString != "") {
        textPayload = textPayload + "&scope=" + scopeString.trim();
    }

    map<string>? parameters = config.parameters;
    if (parameters is map<string>) {
        foreach [string, string] [key, value] in parameters.entries() {
            textPayload = textPayload + "&" + key.trim() + "=" + value.trim();
        }
    }

    if (config.credentialBearer == POST_BODY_BEARER) {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            textPayload = textPayload + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        } else {
            return prepareError("Client ID or client secret is not provided for client authentication.");
        }
    }
    return textPayload;
}

isolated function extractAccessToken(string response, OutboundOAuth2CacheEntry oauth2CacheEntry, int clockSkewInSeconds)
                                     returns string|Error {
    json|error jsonResponse = response.fromJsonString();
    if (jsonResponse is error) {
        return prepareError("Failed to retrieve access token since the response payload is not a JSON.", jsonResponse);
    } else {
        updateOAuth2CacheEntry(jsonResponse, oauth2CacheEntry, clockSkewInSeconds);
        return jsonResponse.access_token.toString();
    }
}

// Updates the OAuth2 token entry with the received JSON payload of the response.
isolated function updateOAuth2CacheEntry(json responsePayload, OutboundOAuth2CacheEntry oauth2CacheEntry,
                                         int clockSkewInSeconds) {
    int issueTime = time:currentTime().time;
    string accessToken = responsePayload.access_token.toString();
    oauth2CacheEntry.accessToken = accessToken;
    json|error expiresIn = responsePayload?.expires_in;
    if (expiresIn is int) {
        oauth2CacheEntry.expTime = issueTime + (expiresIn - clockSkewInSeconds) * 1000;
    }
    if (responsePayload.refresh_token is string) {
        string refreshToken = responsePayload.refresh_token.toString();
        oauth2CacheEntry.refreshToken = refreshToken;
    }
    return ();
}
