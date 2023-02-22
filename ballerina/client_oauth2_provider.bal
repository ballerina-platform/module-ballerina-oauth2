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
import ballerina/url;

const UTF8 = "UTF-8";

# Represents the data structure, which is used to configure the OAuth2 client credentials grant type.
#
# + tokenUrl - Token URL of the token endpoint
# + clientId - Client ID of the client authentication
# + clientSecret - Client secret of the client authentication
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the token endpoint response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the token endpoint
# + clientConfig - HTTP client configurations, which are used to call the token endpoint
public type ClientCredentialsGrantConfig record {|
    string tokenUrl;
    string clientId;
    string clientSecret;
    string|string[] scopes?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# Constant used to infer the values of refreshConfig from values provided for PasswordGrantConfig.
public const INFER_REFRESH_CONFIG = "INFER_REFRESH_CONFIG";

# Represents the data structure, which is used for refresh configuration of the OAuth2 password grant type.
#
# + refreshUrl - Refresh token URL of the token endpoint
# + scopes - Scope(s) of the referesh token request
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credential, which is sent to the token endpoint
# + clientConfig - HTTP client configuration, which is used to call the refresh token endpoint
public type RefreshConfig record {|
    string refreshUrl;
    string|string[] scopes?;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# Represents the data structure, which is used to configure the OAuth2 password grant type.
#
# + tokenUrl - Token URL of the token endpoint
# + username - Username for the password grant type
# + password - Password for the password grant type
# + clientId - Client ID of the client authentication
# + clientSecret - Client secret of the client authentication
# + scopes - Scope(s) of the access request
# + refreshConfig - Configurations for refreshing the access token
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the token endpoint response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the token endpoint
# + clientConfig - HTTP client configurations, which are used to call the token endpoint
public type PasswordGrantConfig record {|
    string tokenUrl;
    string username;
    string password;
    string clientId?;
    string clientSecret?;
    string|string[] scopes?;
    RefreshConfig|INFER_REFRESH_CONFIG refreshConfig?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# Represents the data structure, which is used to configure the OAuth2 refresh token grant type.
#
# + refreshUrl - Refresh token URL of the token endpoint
# + refreshToken - Refresh token for the token endpoint
# + clientId - Client ID of the client authentication
# + clientSecret - Client secret of the client authentication
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the token endpoint response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the token endpoint
# + clientConfig - HTTP client configurations, which are used to call the token endpoint
public type RefreshTokenGrantConfig record {|
    string refreshUrl;
    string refreshToken;
    string clientId;
    string clientSecret;
    string|string[] scopes?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

# Represents the data structure, which is used to configure the OAuth2 JWT bearer grant type.
#
# + tokenUrl - Token URL of the token endpoint
# + assertion - A single JWT for the JWT bearer grant type
# + clientId - Client ID of the client authentication
# + clientSecret - Client secret of the client authentication
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the token endpoint response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the token endpoint
# + clientConfig - HTTP client configurations, which are used to call the token endpoint
public type JwtBearerGrantConfig record {|
    string tokenUrl;
    string assertion;
    string clientId?;
    string clientSecret?;
    string|string[] scopes?;
    decimal defaultTokenExpTime = 3600;
    decimal clockSkew = 0;
    map<string> optionalParams?;
    CredentialBearer credentialBearer = AUTH_HEADER_BEARER;
    ClientConfiguration clientConfig = {};
|};

// The data structure, which stores the values needed to prepare the HTTP request, which are to be sent to the
// token endpoint.
type RequestConfig record {|
    string payload;
    string clientId?;
    string clientSecret?;
    string|string[]? scopes;
    map<string>? optionalParams;
    CredentialBearer credentialBearer;
|};

# Represents the grant type configurations supported for OAuth2.
public type GrantConfig ClientCredentialsGrantConfig|PasswordGrantConfig|RefreshTokenGrantConfig|JwtBearerGrantConfig;

# Represents the client OAuth2 provider, which is used to generate OAuth2 access tokens using the configured OAuth2
# token endpoint configurations. This supports the client credentials grant type, password grant type,
# refresh token grant type, and the JWT bearer grant type.
#
# 1. Client Credentials Grant Type
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     tokenUrl: "https://localhost:9445/oauth2/token",
#     clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#     clientSecret: "9205371918321623741",
#     scopes: ["token-scope1", "token-scope2"]
# });
# ```
#
# 2. Password Grant Type
# ```ballerina
# oauth2:ClientOAuth2Provider provider = new({
#     tokenUrl: "https://localhost:9445/oauth2/token",
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
#     refreshUrl: "https://localhost:9445/oauth2/token",
#     refreshToken: "XlfBs91yquexJqDaKEMzVg==",
#     clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L",
#     clientSecret: "9205371918321623741",
#     scopes: ["token-scope1", "token-scope2"]
# });
# ```
public isolated class ClientOAuth2Provider {

    private final GrantConfig & readonly grantConfig;
    private final TokenCache tokenCache;

    # Provides authorization based on the provided OAuth2 configurations.
    #
    # + grantConfig - OAuth2 grant type configurations
    public isolated function init(GrantConfig grantConfig) {
        self.grantConfig = grantConfig.cloneReadOnly();
        self.tokenCache = new;
        // This generates the token and keep it in the `TokenCache` to be used by the initial request.
        string|Error result = generateOAuth2Token(self.grantConfig, self.tokenCache);
        if result is Error {
            panic result;
        }
    }

    # Get an OAuth2 access token from the token endpoint.
    # ```ballerina
    # string token = check provider.generateToken();
    # ```
    #
    # + return - Received OAuth2 access token or else an `oauth2:Error` if an error occurred
    public isolated function generateToken() returns string|Error {
        string|Error authToken = generateOAuth2Token(self.grantConfig, self.tokenCache);
        if authToken is string {
            return authToken;
        } else {
            return prepareError("Failed to generate OAuth2 token.", authToken);
        }
    }
}

// Generates the OAuth2 access token.
isolated function generateOAuth2Token(GrantConfig grantConfig, TokenCache tokenCache) returns string|Error {
    if grantConfig is ClientCredentialsGrantConfig {
        return getOAuth2TokenForClientCredentialsGrant(grantConfig, tokenCache);
    } else if grantConfig is PasswordGrantConfig {
        return getOAuth2TokenForPasswordGrant(grantConfig, tokenCache);
    } else if grantConfig is RefreshTokenGrantConfig {
        return getOAuth2TokenForRefreshTokenGrantType(grantConfig, tokenCache);
    } else {
        return getOAuth2TokenForJwtBearerGrantType(grantConfig, tokenCache);
    }
}

// Processes the OAuth2 access token for the CLIENT CREDENTIALS GRANT type.
isolated function getOAuth2TokenForClientCredentialsGrant(ClientCredentialsGrantConfig grantConfig,
                                                          TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromTokenRequestForClientCredentialsGrant(grantConfig, tokenCache);
    } else {
        if !tokenCache.isAccessTokenExpired() {
            return cachedAccessToken;
        } else {
            lock {
                if !tokenCache.isAccessTokenExpired() {
                    return tokenCache.getAccessToken();
                }
                return getAccessTokenFromTokenRequestForClientCredentialsGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Processes the OAuth2 access token for the PASSWORD GRANT type.
isolated function getOAuth2TokenForPasswordGrant(PasswordGrantConfig grantConfig, TokenCache tokenCache)
                                                 returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromTokenRequestForPasswordGrant(grantConfig, tokenCache);
    } else {
        if !tokenCache.isAccessTokenExpired() {
            return cachedAccessToken;
        } else {
            lock {
                if !tokenCache.isAccessTokenExpired() {
                    return tokenCache.getAccessToken();
                }
                return getAccessTokenFromRefreshRequestForPasswordGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Processes the OAuth2 access token for the REFRESH TOKEN GRANT type.
isolated function getOAuth2TokenForRefreshTokenGrantType(RefreshTokenGrantConfig grantConfig,
                                                         TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache);
    } else {
        if !tokenCache.isAccessTokenExpired() {
            return cachedAccessToken;
        } else {
            lock {
                if !tokenCache.isAccessTokenExpired() {
                    return tokenCache.getAccessToken();
                }
                return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Processes the OAuth2 access token for the JWT BEARER GRANT type.
isolated function getOAuth2TokenForJwtBearerGrantType(JwtBearerGrantConfig grantConfig,
                                                      TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromTokenRequestForJwtBearerGrant(grantConfig, tokenCache);
    } else {
        if !tokenCache.isAccessTokenExpired() {
            return cachedAccessToken;
        } else {
            lock {
                if !tokenCache.isAccessTokenExpired() {
                    return tokenCache.getAccessToken();
                }
                return getAccessTokenFromRefreshRequestForJwtBearerGrant(grantConfig, tokenCache);
            }
        }
    }
}

// Requests an access token from the token endpoint using the provided CLIENT CREDENTIALS GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-4.4
isolated function getAccessTokenFromTokenRequestForClientCredentialsGrant(ClientCredentialsGrantConfig config,
                                                                          TokenCache tokenCache) returns string|Error {
    if config.clientId == "" || config.clientSecret == "" {
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
    tokenCache.update(accessToken, (), expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

// Requests an access token from the token endpoint using the provided PASSWORD GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-4.3
isolated function getAccessTokenFromTokenRequestForPasswordGrant(PasswordGrantConfig config,
                                                                 TokenCache tokenCache) returns string|Error {
    string tokenUrl = config.tokenUrl;
    string? clientId = config?.clientId;
    string? clientSecret = config?.clientSecret;
    [string, string] [username, password] = check getEncodedUsernamePassword(config.username, config.password);
    string payload = string `grant_type=password&username=${username}&password=${password}`;
    RequestConfig requestConfig;
    if clientId is string && clientSecret is string {
        if clientId == "" || clientSecret == "" {
            return prepareError("Client-id or client-secret cannot be empty.");
        }
        requestConfig = {
            payload,
            clientId,
            clientSecret,
            scopes: config?.scopes,
            optionalParams: config?.optionalParams,
            credentialBearer: config.credentialBearer
        };
    } else {
        requestConfig = {
            payload,
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
    tokenCache.update(accessToken, refreshToken, expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

isolated function getEncodedUsernamePassword(string username, string password) returns [string,string]|Error {
    do {
        string encodedUserName = check url:encode(username, UTF8);
        string encodedPassword = check url:encode(password, UTF8);
        return [encodedUserName, encodedPassword];
    } on fail error err {
        return prepareError("Error while encoding the username or password.", err);
    }
}

// Requests an access token from the token endpoint using the provided JWT BEARER GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc7523#section-2.1
isolated function getAccessTokenFromTokenRequestForJwtBearerGrant(JwtBearerGrantConfig config,
                                                                  TokenCache tokenCache) returns string|Error {
    string tokenUrl = config.tokenUrl;
    string? clientId = config?.clientId;
    string? clientSecret = config?.clientSecret;
    RequestConfig requestConfig;
    if clientId is string && clientSecret is string {
        if clientId == "" || clientSecret == "" {
            return prepareError("Client-id or client-secret cannot be empty.");
        }
        requestConfig = {
            payload: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + config.assertion,
            clientId: clientId,
            clientSecret: clientSecret,
            scopes: config?.scopes,
            optionalParams: config?.optionalParams,
            credentialBearer: config.credentialBearer
        };
    } else {
        requestConfig = {
            payload: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + config.assertion,
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
    tokenCache.update(accessToken, refreshToken, expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

// Refreshes an access token from the token endpoint using the provided refresh configurations of the PASSWORD GRANT configurations.
// For information, see [Refreshing an Access Token](https://tools.ietf.org/html/rfc6749#section-6).
isolated function getAccessTokenFromRefreshRequestForPasswordGrant(PasswordGrantConfig config, TokenCache tokenCache)
                                                                   returns string|Error {
    RefreshConfig refreshConfig = check getRefreshConfig(config);
    string? clientId = config?.clientId;
    string? clientSecret = config?.clientSecret;
    if clientId is () || clientSecret is () {
        return prepareError("Client-id or client-secret cannot be empty.");
    }

    // Checking `(clientId == "" || clientSecret == "")` is validated while requesting access token by token
    // request, initially.
    string refreshToken = tokenCache.getRefreshToken();
    if refreshToken == "" {
        // The subsequent requests should have a cached `refreshToken` to refresh the access token.
        return prepareError("Failed to refresh access token since refresh-token has not been cached from the initial authorization response.");
    }
    RequestConfig requestConfig = {
        payload: "grant_type=refresh_token&refresh_token=" + refreshToken,
        clientId: clientId,
        clientSecret: clientSecret,
        scopes: refreshConfig?.scopes,
        optionalParams: refreshConfig?.optionalParams,
        credentialBearer: refreshConfig.credentialBearer
    };

    json response = check sendRequest(requestConfig, refreshConfig.refreshUrl,refreshConfig.clientConfig);
    string accessToken = check extractAccessToken(response);
    string? updatedRefreshToken = extractRefreshToken(response);
    int? expiresIn = extractExpiresIn(response);
    tokenCache.update(accessToken, updatedRefreshToken, expiresIn, config.defaultTokenExpTime, config.clockSkew);
    return accessToken;
}

isolated function getRefreshConfig(PasswordGrantConfig config) returns RefreshConfig|Error {
    RefreshConfig|INFER_REFRESH_CONFIG? refreshConfig = config?.refreshConfig;
    if refreshConfig is () {
        return prepareError("Failed to refresh access token since refresh configurations are not provided.");
    }
    if refreshConfig is INFER_REFRESH_CONFIG {
        return {
            refreshUrl: config.tokenUrl,
            optionalParams: config.optionalParams,
            credentialBearer: config.credentialBearer,
            clientConfig: config.clientConfig
        };
    }
    return refreshConfig;
}

// Refreshes an access token from the token endpoint using the provided REFRESH TOKEN GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-6
isolated function getAccessTokenFromRefreshRequestForRefreshTokenGrant(RefreshTokenGrantConfig config,
                                                                       TokenCache tokenCache) returns string|Error {
    if config.clientId == "" || config.clientSecret == "" {
        return prepareError("Client-id or client-secret cannot be empty.");
    }
    string refreshUrl = config.refreshUrl;
    // The initial request does not have a cached `refreshToken`. Also, the subsequent requests also may not have
    // a cached `refreshToken` since the token endpoint does not update the `refreshToken`.
    // Hence, the `config.refreshToken` is used.
    // Refer: https://tools.ietf.org/html/rfc6749#page-48
    string refreshToken = tokenCache.getRefreshToken();
    if refreshToken == "" {
        refreshToken = config.refreshToken;
    }
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
    tokenCache.update(accessToken, updatedRefreshToken, expiresIn, defaultTokenExpTime, clockSkew);
    return accessToken;
}

// Refreshes an access token from the token endpoint using the provided JWT BEARER GRANT configurations.
// Refer: https://tools.ietf.org/html/rfc6749#section-6
isolated function getAccessTokenFromRefreshRequestForJwtBearerGrant(JwtBearerGrantConfig config,
                                                                    TokenCache tokenCache) returns string|Error {
    string? clientId = config?.clientId;
    string? clientSecret = config?.clientSecret;
    if clientId is string && clientSecret is string {
        // Checking `(clientId == "" || clientSecret == "")` is validated while requesting access token by token
        // request, initially.
        string refreshUrl = config.tokenUrl;
        string refreshToken = tokenCache.getRefreshToken();
        if refreshToken == "" {
            // The subsequent requests should have a cached `refreshToken` to refresh the access token.
            return prepareError("Failed to refresh access token since refresh-token has not been cached from the initial authorization response.");
        }
        RequestConfig requestConfig = {
            payload: "grant_type=refresh_token&refresh_token=" + refreshToken,
            clientId: clientId,
            clientSecret: clientSecret,
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
        tokenCache.update(accessToken, updatedRefreshToken, expiresIn, defaultTokenExpTime, clockSkew);
        return accessToken;
    }
    return prepareError("Client-id or client-secret cannot be empty.");
}

isolated function sendRequest(RequestConfig requestConfig, string url, ClientConfiguration clientConfig)
                              returns json|Error {
    map<string> headers = check prepareHeaders(requestConfig);
    string payload = check preparePayload(requestConfig);
    string|Error stringResponse = doHttpRequest(url, clientConfig, headers, payload);
    if stringResponse is string {
        json|error jsonResponse = stringResponse.fromJsonString();
        if jsonResponse is json {
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
    if config.credentialBearer == AUTH_HEADER_BEARER {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if clientId is string && clientSecret is string {
            string clientIdSecret = clientId + ":" + clientSecret;
            headers["Authorization"] = "Basic " + clientIdSecret.toBytes().toBase64();
        }
    }
    return headers;
}

isolated function preparePayload(RequestConfig config) returns string|Error {
    string textPayload = config.payload;
    string scopeString = "";
    string|string[]? scopes = config.scopes;
    if scopes is string {
        scopeString += scopes.trim();
    } else if scopes is string[] {
        foreach string requestScope in scopes {
            string trimmedRequestScope = requestScope.trim();
            if trimmedRequestScope != "" {
                scopeString = scopeString + " " + trimmedRequestScope;
            }
        }
    }
    if scopeString != "" {
        textPayload = textPayload + "&scope=" + scopeString.trim();
    }

    map<string>? optionalParams = config.optionalParams;
    if optionalParams is map<string> {
        foreach [string, string] [key, value] in optionalParams.entries() {
            textPayload = textPayload + "&" + key.trim() + "=" + value.trim();
        }
    }

    if config.credentialBearer == POST_BODY_BEARER {
        string? clientId = config?.clientId;
        string? clientSecret = config?.clientSecret;
        if clientId is string && clientSecret is string {
            textPayload = textPayload + "&client_id=" + clientId + "&client_secret=" + clientSecret;
        }
    }
    return textPayload;
}

isolated function extractAccessToken(json response) returns string|Error {
    json|error accessToken = response.access_token;
    if accessToken is string {
        return accessToken;
    } else if accessToken is error {
        return prepareError("Failed to access 'access_token' property from the JSON.", accessToken);
    }
    return prepareError("Failed to extract 'access_token' property as a 'string' from the JSON.");
}

isolated function extractRefreshToken(json response) returns string? {
    json|error refreshToken = response.refresh_token;
    if refreshToken is string {
        return refreshToken;
    }
    log:printDebug("Failed to access 'refresh_token' property from the JSON.");
    return;
}

isolated function extractExpiresIn(json response) returns int? {
    json|error expiresIn = response.expires_in;
    if expiresIn is int {
        return expiresIn;
    }
    log:printDebug("Failed to access 'expires_in' property from the JSON as an int.");
    return;
}

// This class stores the values received from the token/introspection endpoint to use them for the latter requests
// without requesting tokens again.
isolated class TokenCache {

    private string accessToken;
    private string refreshToken;
    private int expTime;

    isolated function init() {
        self.accessToken = "";
        self.refreshToken = "";
        self.expTime = -1;
    }

    isolated function getAccessToken() returns string {
        lock {
            return self.accessToken;
        }
    }

    isolated function getRefreshToken() returns string {
        lock {
            return self.refreshToken;
        }
    }

    // Checks the validity of the cached access token by analyzing the expiry time.
    isolated function isAccessTokenExpired() returns boolean {
        lock {
            [int, decimal] currentTime = time:utcNow();
            if currentTime[0] < self.expTime {
                return false;
            }
            return true;
        }
    }

    // Updates the cache with the values received from JSON payload of the response.
    isolated function update(string accessToken, string? refreshToken, int? expiresIn, decimal defaultTokenExpTime, decimal clockSkew) {
        lock {
            self.accessToken = accessToken;
            [int, decimal] currentTime = time:utcNow();
            int issueTime = currentTime[0];
            if expiresIn is int {
                self.expTime = issueTime + expiresIn - <int> clockSkew;
            } else {
                self.expTime = issueTime + <int> (defaultTokenExpTime - clockSkew);
            }
            if refreshToken is string {
                self.refreshToken = refreshToken;
            }
        }
    }
}
