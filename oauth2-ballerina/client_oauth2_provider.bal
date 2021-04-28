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

import ballerina/log;
import ballerina/time;

# The data structure, which is used to configure the OAuth2 client credentials grant type.
#
# + tokenUrl - Token URL for the authorization endpoint
# + clientId - Client ID for the client credentials grant authentication
# + clientSecret - Client secret for the client credentials grant authentication
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the authorization server response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of optional parameters use for the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type ClientCredentialsGrantConfig record {|
    string tokenUrl;
    string clientId;
    string clientSecret;
    string[] scopes?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
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
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the authorization server response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of optional parameters use for the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type PasswordGrantConfig record {|
    string tokenUrl;
    string username;
    string password;
    string clientId?;
    string clientSecret?;
    string[] scopes?;
    record {|
        string refreshUrl;
        string[] scopes?;
        map<string> optionalParams?;
        CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
        ClientConfiguration clientConfig = {};
    |} refreshConfig?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# The data structure, which can be used to configure OAuth2 refresh token grant type.
#
# + refreshUrl - Refresh token URL for the refresh token server
# + refreshToken - Refresh token for the refresh token server
# + clientId - Client ID for authentication with the authorization endpoint
# + clientSecret - Client secret for authentication with the authorization endpoint
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the authorization server response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of optional parameters use for the authorization endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the authorization endpoint
# + clientConfig - HTTP client configurations, which are used to call the authorization endpoint
public type RefreshTokenGrantConfig record {|
    string refreshUrl;
    string refreshToken;
    string clientId;
    string clientSecret;
    string[] scopes?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

// The data structure, which stores the values received from the authorization/token server to use them
// for the latter requests without requesting tokens again.
type TokenCache record {
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
    map<string>? optionalParams;
    CredentialBearer credentialBearer;
|};

# Represents the grant type configurations supported for OAuth2.
public type GrantConfig ClientCredentialsGrantConfig|PasswordGrantConfig|RefreshTokenGrantConfig;

# Represents the client OAuth2 provider, which generates OAuth2 tokens. This supports the client credentials grant type,
# password grant type, and the refresh token grant type.
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
# 3. Refresh Token Grant Type
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     refreshUrl: "https://localhost:9196/oauth2/token/refresh",
#     refreshToken: "XlfBs91yquexJqDaKEMzVg==",
#     clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#     clientSecret: "9205371918321623741",
#     scopes: ["token-scope1", "token-scope2"]
# });
# ```
public class ClientOAuth2Provider {

    GrantConfig grantConfig;
    TokenCache tokenCache;

    # Provides authentication based on the provided OAuth2 configurations.
    #
    # + grantConfig - OAuth2 grant type configurations
    public isolated function init(GrantConfig grantConfig) {
        self.grantConfig = grantConfig;
        self.tokenCache = initTokenCache();
        // This generates the token and keep it in the `TokenCache` to be used by the initial request.
        string|Error result = generateOAuth2Token(self.grantConfig, self.tokenCache);
        if (result is Error) {
            panic result;
        }
    }

    # Get an OAuth2 access token from authorization server for the OAuth2 authentication.
    # ```ballerina
    # string:oauth2:Error token = provider.generateToken();
    # ```
    #
    # + return - Generated OAuth2 token or else an `oauth2:Error` if an error occurred
    public isolated function generateToken() returns string|Error {
        string|Error authToken = generateOAuth2Token(self.grantConfig, self.tokenCache);
        if (authToken is string) {
            return authToken;
        } else {
            return prepareError("Failed to generate OAuth2 token.", authToken);
        }
    }
}

// Generates the OAuth2 token.
isolated function generateOAuth2Token(GrantConfig grantConfig, TokenCache tokenCache) returns string|Error {
    if (grantConfig is ClientCredentialsGrantConfig) {
        return getOAuth2TokenForClientCredentialsGrant(grantConfig, tokenCache);
    } else if (grantConfig is PasswordGrantConfig) {
        return getOAuth2TokenForPasswordGrant(grantConfig, tokenCache);
    } else {
        return getOAuth2TokenForRefreshTokenGrantType(grantConfig, tokenCache);
    }
}

// Processes the OAuth2 token for the CLIENT CREDENTIALS GRANT type.
isolated function getOAuth2TokenForClientCredentialsGrant(ClientCredentialsGrantConfig grantConfig,
                                                          TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == "") {
        return getAccessTokenFromTokenRequestForClientCredentialsGrant(grantConfig, tokenCache);
    } else {
        if (isCachedTokenValid(tokenCache.expTime)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache.expTime)) {
                    return tokenCache.accessToken;
                }
                return getAccessTokenFromTokenRequestForClientCredentialsGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Processes the OAuth2 token for the PASSWORD GRANT type.
isolated function getOAuth2TokenForPasswordGrant(PasswordGrantConfig grantConfig, TokenCache tokenCache)
                                                 returns string|Error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == "") {
        return getAccessTokenFromTokenRequestForPasswordGrant(grantConfig, tokenCache);
    } else {
        if (isCachedTokenValid(tokenCache.expTime)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache.expTime)) {
                    return tokenCache.accessToken;
                }
                return getAccessTokenFromRefreshRequestForPasswordGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Processes the OAuth2 token for the REFRESH TOKEN GRANT type.
isolated function getOAuth2TokenForRefreshTokenGrantType(RefreshTokenGrantConfig grantConfig,
                                                         TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.accessToken;
    if (cachedAccessToken == "") {
        return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache);
    } else {
        if (isCachedTokenValid(tokenCache.expTime)) {
            return cachedAccessToken;
        } else {
            lock {
                if (isCachedTokenValid(tokenCache.expTime)) {
                    return tokenCache.accessToken;
                }
                return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Requests an access-token from the token endpoint using the provided CLIENT CREDENTIALS GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-4.4
isolated function getAccessTokenFromTokenRequestForClientCredentialsGrant(ClientCredentialsGrantConfig config,
                                                                          TokenCache tokenCache) returns string|Error {
    if (config.clientId == "" || config.clientSecret == "") {
        return prepareError("Client-id or client-secret cannot be empty.");
    }
    string tokenUrl = config.tokenUrl;
    RequestConfig requestConfig = {
        payload: "grant_type=client_credentials",
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scopes: config?.scopes,
        optionalParams: config?.optionalParams,
        credentialBearer: config.credentialBearer
    };
    decimal defaultTokenExpTime = config.defaultTokenExpTime;
    decimal clockSkew = config.clockSkew;
    ClientConfiguration clientConfig = config.clientConfig;

    json response = check sendRequest(requestConfig, tokenUrl, clientConfig);
    string accessToken = check extractAccessToken(response);
    int? expiresIn = extractExpiresIn(response);
    updateTokenCache(tokenCache, accessToken, (), expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

// Requests an access-token from the token endpoint using the provided PASSWORD GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-4.3
isolated function getAccessTokenFromTokenRequestForPasswordGrant(PasswordGrantConfig config,
                                                                 TokenCache tokenCache) returns string|Error {
    string tokenUrl = config.tokenUrl;
    string? clientId = config?.clientId;
    string? clientSecret = config?.clientSecret;
    RequestConfig requestConfig;
    if (clientId is string && clientSecret is string) {
        if (clientId == "" || clientSecret == "") {
            return prepareError("Client-id or client-secret cannot be empty.");
        }
        requestConfig = {
            payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
            clientId: clientId,
            clientSecret: clientSecret,
            scopes: config?.scopes,
            optionalParams: config?.optionalParams,
            credentialBearer: config.credentialBearer
        };
    } else {
        requestConfig = {
            payload: "grant_type=password&username=" + config.username + "&password=" + config.password,
            scopes: config?.scopes,
            optionalParams: config?.optionalParams,
            credentialBearer: config.credentialBearer
        };
    }
    decimal defaultTokenExpTime = config.defaultTokenExpTime;
    decimal clockSkew = config.clockSkew;
    ClientConfiguration clientConfig = config.clientConfig;

    json response = check sendRequest(requestConfig, tokenUrl, clientConfig);
    string accessToken = check extractAccessToken(response);
    string? refreshToken = extractRefreshToken(response);
    int? expiresIn = extractExpiresIn(response);
    updateTokenCache(tokenCache, accessToken, refreshToken, expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

// Refreshes an access-token from the token endpoint using the provided refresh configurations of PASSWORD GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-6
isolated function getAccessTokenFromRefreshRequestForPasswordGrant(PasswordGrantConfig config, TokenCache tokenCache)
                                                                   returns string|Error {
    var refreshConfig = config?.refreshConfig;
    if (refreshConfig is ()) {
        return prepareError("Failed to refresh access-token since refresh configurations are not provided.");
    } else {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            if (clientId == "" || clientSecret == "") {
                return prepareError("Client-id or client-secret cannot be empty.");
            }
            string refreshUrl = refreshConfig.refreshUrl;
            string refreshToken = tokenCache.refreshToken;
            if (refreshToken == "") {
                // The subsequent requests should have a cached `refreshToken` to refresh the access-token.
                return prepareError("Failed to refresh access-token since refresh-token has not been cached from the initial authorization response.");
            }
            RequestConfig requestConfig = {
                payload: "grant_type=refresh_token&refresh_token=" + tokenCache.refreshToken,
                clientId: clientId,
                clientSecret: clientSecret,
                scopes: refreshConfig?.scopes,
                optionalParams: refreshConfig?.optionalParams,
                credentialBearer: refreshConfig.credentialBearer
            };
            ClientConfiguration clientConfig = refreshConfig.clientConfig;
            decimal defaultTokenExpTime = config.defaultTokenExpTime;
            decimal clockSkew = config.clockSkew;

            json response = check sendRequest(requestConfig, refreshUrl, clientConfig);
            string accessToken = check extractAccessToken(response);
            string? updatedRefreshToken = extractRefreshToken(response);
            int? expiresIn = extractExpiresIn(response);
            updateTokenCache(tokenCache, accessToken, updatedRefreshToken, expiresIn, defaultTokenExpTime, clockSkew);
            return accessToken;
        } else {
            return prepareError("Client-id or client-secret cannot be empty.");
        }
    }
}

// Refreshes an access-token from the token endpoint using the provided REFRESH TOKEN GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-6
isolated function getAccessTokenFromRefreshRequestForRefreshTokenGrant(RefreshTokenGrantConfig config,
                                                                       TokenCache tokenCache) returns string|Error {
    if (config.clientId == "" || config.clientSecret == "") {
        return prepareError("Client-id or client-secret cannot be empty.");
    }
    string refreshUrl = config.refreshUrl;
    // The initial request does not have a cached `refreshToken`. Also, the subsequent requests also may not have
    // a cached `refreshToken` since the authorization server does not update the `refreshToken`.
    // Hence, the `config.refreshToken` is used.
    // Refer: https://tools.ietf.org/html/rfc6749#page-48
    string refreshToken = (tokenCache.refreshToken != "") ? (tokenCache.refreshToken) : (config.refreshToken);
    RequestConfig requestConfig = {
        payload: "grant_type=refresh_token&refresh_token=" + refreshToken,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scopes: config?.scopes,
        optionalParams: config?.optionalParams,
        credentialBearer: config.credentialBearer
    };
    ClientConfiguration clientConfig = config.clientConfig;
    decimal defaultTokenExpTime = config.defaultTokenExpTime;
    decimal clockSkew = config.clockSkew;

    json response = check sendRequest(requestConfig, refreshUrl, clientConfig);
    string accessToken = check extractAccessToken(response);
    string? updatedRefreshToken = extractRefreshToken(response);
    int? expiresIn = extractExpiresIn(response);
    updateTokenCache(tokenCache, accessToken, updatedRefreshToken, expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

isolated function sendRequest(RequestConfig requestConfig, string url, ClientConfiguration clientConfig)
                              returns json|Error {
    map<string> headers = check prepareHeaders(requestConfig);
    string payload = check preparePayload(requestConfig);
    string|Error stringResponse = doHttpRequest(url, clientConfig, headers, payload);
    if (stringResponse is string) {
        json|error jsonResponse = stringResponse.fromJsonString();
        if (jsonResponse is json) {
            return jsonResponse;
        } else {
            return prepareError("Failed to get JSON from the response payload.", jsonResponse);
        }
    } else {
        return prepareError("Failed to call the token endpoint '" + url + "'.", stringResponse);
    }
}

isolated function prepareHeaders(RequestConfig config) returns map<string>|Error {
    map<string> headers = {};
    if (config.credentialBearer == AUTH_HEADER_BEARER) {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            string clientIdSecret = clientId + ":" + clientSecret;
            headers["Authorization"] = "Basic " + clientIdSecret.toBytes().toBase64();
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

    map<string>? optionalParams = config.optionalParams;
    if (optionalParams is map<string>) {
        foreach [string, string] [key, value] in optionalParams.entries() {
            textPayload = textPayload + "&" + key.trim() + "=" + value.trim();
        }
    }

    if (config.credentialBearer == POST_BODY_BEARER) {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if (clientId is string && clientSecret is string) {
            textPayload = textPayload + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        }
    }
    return textPayload;
}

isolated function extractAccessToken(json response) returns string|Error {
    json|error accessToken = response.access_token;
    if (accessToken is json) {
        return accessToken.toJsonString();
    } else {
        return prepareError("Failed to access 'access_token' property from the JSON.", accessToken);
    }
}

isolated function extractRefreshToken(json response) returns string? {
    json|error refreshToken = response.refresh_token;
    if (refreshToken is json) {
        return refreshToken.toJsonString();
    } else {
        log:printDebug("Failed to access 'refresh_token' property from the JSON.");
    }
}

isolated function extractExpiresIn(json response) returns int? {
    json|error expiresIn = response.expires_in;
    if (expiresIn is int) {
        return expiresIn;
    } else {
        log:printDebug("Failed to access 'expires_in' property from the JSON as an int.");
    }
}

// Checks the validity of the cached access-token.
isolated function isCachedTokenValid(int expTime) returns boolean {
    [int, decimal] currentTime = time:utcNow();
    if (currentTime[0] < expTime) {
        return true;
    }
    return false;
}

// Updates the OAuth2 token cache with the received JSON payload of the response.
isolated function updateTokenCache(TokenCache tokenCache, string accessToken, string? refreshToken, int? expiresIn,
                                   decimal defaultTokenExpTime, decimal clockSkew) {
    tokenCache.accessToken = accessToken;
    [int, decimal] currentTime = time:utcNow();
    int issueTime = currentTime[0];
    if (expiresIn is int) {
        tokenCache.expTime = issueTime + expiresIn - <int> clockSkew;
    } else {
        tokenCache.expTime = issueTime + <int> (defaultTokenExpTime - clockSkew);
    }
    if (refreshToken is string) {
        tokenCache.refreshToken = refreshToken.toJsonString();
    }
}

// Initialize OAuth2 token cache with the default exp time and empty values.
isolated function initTokenCache() returns TokenCache {
    TokenCache tokenCache = {
        accessToken: "",
        refreshToken: "",
        expTime: -1
    };
    return tokenCache;
}
