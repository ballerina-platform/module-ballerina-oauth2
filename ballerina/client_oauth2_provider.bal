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

# Pluggable storage hooks for Refresh Token Rotation (RFC 6749 section 6).
#
# A `RefreshTokenStore` is a pair of isolated function references — one to read
# the currently-stored refresh token, one to atomically replace it — so the
# surrounding `RefreshTokenGrantConfig` remains `Cloneable` / deep-freezable.
#
# Implementations persist the rotated `refresh_token` so it survives process
# restarts and can be shared across replicas in containerised deployments.
#
# **Concurrency contract (multi-replica safety)**
#
# The race window in RTR is: read token → call token endpoint → write rotated token.
# Two replicas reading the same `refresh_token` concurrently and both refreshing it
# can cause one replica to invalidate the other's token. A plain set() cannot close
# this window; only an atomic compare-and-set can. `compareAndSetRefreshToken` MUST
# use a backend-level atomic primitive (e.g. Redis `SET NX/XX`, a database row lock,
# or a distributed lease) so that only the first writer wins.
#
# When supplied via `RefreshTokenGrantConfig.tokenStore`, the store is the source of
# truth: the provider reads the token via `getRefreshToken` before each call to the
# token endpoint, then attempts to atomically replace it via `compareAndSetRefreshToken`.
# If the CAS fails (another replica already rotated the token), the provider discards
# its own rotated value and lets the store's winner be picked up on the next refresh.
#
# + getRefreshToken - Returns the currently stored refresh token, or `""` if none is
#                     stored (in which case the provider falls back to
#                     `RefreshTokenGrantConfig.refreshToken`).
# + compareAndSetRefreshToken - Atomically replaces the stored refresh token with
#                               `updated` only if the current stored value equals
#                               `expected`. Returns `true` if the swap succeeded,
#                               `false` if another replica already rotated the token
#                               (the provider will discard `updated` and re-read the
#                               store on the next refresh). Implementations MUST use
#                               a backend atomic primitive to ensure correctness.
public type RefreshTokenStore record {|
    isolated function () returns string|Error getRefreshToken;
    isolated function (string expected, string updated) returns boolean|Error compareAndSetRefreshToken;
|};

# Represents the data structure, which is used to configure the OAuth2 refresh token grant type.
#
# + refreshUrl - Refresh token URL of the token endpoint
# + refreshToken - Refresh token for the token endpoint (used as the seed when `tokenStore` is empty)
# + clientId - Client ID of the client authentication
# + clientSecret - Client secret of the client authentication
# + scopes - Scope(s) of the access request
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the token endpoint response does not contain an `expires_in` field
# + clockSkew - Clock skew (in seconds) that can be used to avoid token validation failures due to clock synchronization problems
# + optionalParams - Map of the optional parameters used for the token endpoint
# + credentialBearer - Bearer of the authentication credentials, which is sent to the token endpoint
# + clientConfig - HTTP client configurations, which are used to call the token endpoint
# + tokenStore - Optional pluggable store for the rotated refresh token. Persists the latest rotated
#                `refresh_token` across process restarts and shares it across replicas, enabling
#                restart-resilient and multi-replica Refresh Token Rotation (RFC 6749 section 6).
#                `isolated function` values are `readonly` and therefore `Cloneable`, so this field
#                does not break `cloneReadOnly()`. It is NOT `anydata`, so callers that invoke
#                `cloneWithType()` on this config (e.g. the Salesforce connector listener) must
#                handle `RefreshTokenGrantConfig` separately before calling `cloneWithType()`.
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
    RefreshTokenStore tokenStore?;
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
    // Pluggable RTR store — stored as separate isolated function references so
    // Ballerina's isolated-class type system accepts them as final fields.
    private final (isolated function () returns string|Error)? storeGet;
    private final (isolated function (string, string) returns boolean|Error)? storeSet;

    # Provides authorization based on the provided OAuth2 configurations.
    #
    # + grantConfig - OAuth2 grant type configurations. For `RefreshTokenGrantConfig`, the optional
    #                 `tokenStore` field enables restart-resilient and multi-replica Refresh Token
    #                 Rotation (RFC 6749 section 6): the provider reads the current refresh token
    #                 from the store before each refresh and writes the rotated token back after
    #                 every successful response that includes a new `refresh_token`.
    #                 When `tokenStore` is absent the in-process `TokenCache` is used (correct for
    #                 single-replica deployments).
    public isolated function init(GrantConfig grantConfig) {
        self.grantConfig = grantConfig.cloneReadOnly();
        self.tokenCache = new;
        // Extract the RefreshTokenStore from RefreshTokenGrantConfig if provided.
        // isolated function values are readonly → Cloneable, so cloneReadOnly() above succeeds.
        // They are NOT anydata, so we store the references separately rather than keeping them
        // in self.grantConfig where downstream anydata checks (e.g. in connectors) might object.
        RefreshTokenStore? store = grantConfig is RefreshTokenGrantConfig ? grantConfig?.tokenStore : ();
        self.storeGet = store is RefreshTokenStore ? store.getRefreshToken : ();
        self.storeSet = store is RefreshTokenStore ? store.compareAndSetRefreshToken : ();
        // This generates the token and keep it in the `TokenCache` to be used by the initial request.
        string|Error result = generateOAuth2Token(self.grantConfig, self.tokenCache, self.storeGet, self.storeSet);
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
        string|Error authToken = generateOAuth2Token(self.grantConfig, self.tokenCache, self.storeGet, self.storeSet);
        if authToken is string {
            return authToken;
        }
        return prepareError("Failed to generate OAuth2 token.", authToken);
    }
}

// Generates the OAuth2 access token.
isolated function generateOAuth2Token(GrantConfig grantConfig, TokenCache tokenCache,
        (isolated function () returns string|Error)? storeGet = (),
        (isolated function (string, string) returns boolean|Error)? storeSet = ()) returns string|Error {
    if grantConfig is ClientCredentialsGrantConfig {
        return getOAuth2TokenForClientCredentialsGrant(grantConfig, tokenCache);
    } else if grantConfig is PasswordGrantConfig {
        return getOAuth2TokenForPasswordGrant(grantConfig, tokenCache);
    } else if grantConfig is RefreshTokenGrantConfig {
        return getOAuth2TokenForRefreshTokenGrantType(grantConfig, tokenCache, storeGet, storeSet);
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
    } 
    if !tokenCache.isAccessTokenExpired() {
        return cachedAccessToken;
    }
    lock {
        if !tokenCache.isAccessTokenExpired() {
            return tokenCache.getAccessToken();
        }
        return getAccessTokenFromTokenRequestForClientCredentialsGrant(grantConfig, tokenCache);
    }
}

// Processes the OAuth2 access token for the PASSWORD GRANT type.
isolated function getOAuth2TokenForPasswordGrant(PasswordGrantConfig grantConfig, TokenCache tokenCache)
                                                 returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromTokenRequestForPasswordGrant(grantConfig, tokenCache);
    }
    if !tokenCache.isAccessTokenExpired() {
        return cachedAccessToken;
    }
    lock {
        if !tokenCache.isAccessTokenExpired() {
            return tokenCache.getAccessToken();
        }
        return getAccessTokenFromRefreshRequestForPasswordGrant(grantConfig, tokenCache);
    }
}

// Processes the OAuth2 access token for the REFRESH TOKEN GRANT type.
isolated function getOAuth2TokenForRefreshTokenGrantType(RefreshTokenGrantConfig grantConfig,
        TokenCache tokenCache,
        (isolated function () returns string|Error)? storeGet = (),
        (isolated function (string, string) returns boolean|Error)? storeSet = ()) returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache, storeGet, storeSet);
    }
    if !tokenCache.isAccessTokenExpired() {
        return cachedAccessToken;
    }
    lock {
        if !tokenCache.isAccessTokenExpired() {
            return tokenCache.getAccessToken();
        }
        return getAccessTokenFromRefreshRequestForRefreshTokenGrant(grantConfig, tokenCache, storeGet, storeSet);
    }
}

// Processes the OAuth2 access token for the JWT BEARER GRANT type.
isolated function getOAuth2TokenForJwtBearerGrantType(JwtBearerGrantConfig grantConfig,
                                                      TokenCache tokenCache) returns string|Error {
    string cachedAccessToken = tokenCache.getAccessToken();
    if cachedAccessToken == "" {
        return getAccessTokenFromTokenRequestForJwtBearerGrant(grantConfig, tokenCache);
    }
    if !tokenCache.isAccessTokenExpired() {
        return cachedAccessToken;
    }
    lock {
        if !tokenCache.isAccessTokenExpired() {
            return tokenCache.getAccessToken();
        }
        return getAccessTokenFromRefreshRequestForJwtBearerGrant(grantConfig, tokenCache);
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
    // The refresh token must have been cached from the initial authorization response.
    // If the token endpoint returns a new `refresh_token` (Refresh Token Rotation per RFC 6749 section 6),
    // it is stored in the cache and used for all subsequent refresh requests, replacing the previous token.
    // If the token endpoint does not return a new `refresh_token`, the existing cached token is preserved.
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

    json response = check sendRequest(requestConfig, refreshConfig.refreshUrl, refreshConfig.clientConfig);
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
        TokenCache tokenCache,
        (isolated function () returns string|Error)? storeGet = (),
        (isolated function (string, string) returns boolean|Error)? storeSet = ()) returns string|Error {
    if config.clientId == "" || config.clientSecret == "" {
        return prepareError("Client-id or client-secret cannot be empty.");
    }
    string refreshUrl = config.refreshUrl;
    // Refresh Token Rotation (RFC 6749 section 6).
    //
    // Source of truth for the current refresh token:
    //   1. storeGet (if configured via ClientOAuth2Provider constructor) — survives
    //      process restarts and is shared across replicas. Required for containerised /
    //      multi-replica deployments.
    //   2. The in-process TokenCache — populated after the first successful refresh.
    //   3. config.refreshToken — the bootstrap seed used until the store / cache
    //      has a rotated value.
    //
    // When the token endpoint returns a new refresh_token, it is persisted via
    // storeSet (if any) and the cache. When the endpoint omits refresh_token (or
    // returns an empty one), the existing stored/cached value is preserved.
    string refreshToken = "";
    if storeGet is isolated function () returns string|Error {
        refreshToken = check storeGet();
    }
    if refreshToken == "" {
        refreshToken = tokenCache.getRefreshToken();
    }
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
    // Atomically persist the rotated refresh token to the external store.
    // Using CAS (compare-and-set) closes the multi-replica race: only the first
    // replica to finish the token-endpoint call wins the write. If another replica
    // already wrote a newer token (CAS returns false), discard our rotated value —
    // the store's winner will be picked up via storeGet on the next refresh.
    if storeSet is isolated function (string, string) returns boolean|Error && updatedRefreshToken is string {
        boolean swapped = check storeSet(refreshToken, updatedRefreshToken);
        if !swapped {
            log:printWarn("RTR compare-and-set skipped: another replica already rotated the refresh token.");
            tokenCache.update(accessToken, (), expiresIn, defaultTokenExpTime, clockSkew);
            return accessToken;
        }
    }
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
        // The refresh token must have been cached from the initial authorization response.
        // If the token endpoint returns a new `refresh_token` (Refresh Token Rotation per RFC 6749 section 6),
        // it is stored in the cache and used for all subsequent refresh requests, replacing the previous token.
        // If the token endpoint does not return a new `refresh_token`, the existing cached token is preserved.
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
        }
        return prepareError("Failed to get JSON from the response payload.", jsonResponse);
    }
    return prepareError("Failed to call the token endpoint '" + url + "'.", stringResponse);
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
    if refreshToken is string && refreshToken != "" {
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
    // If `refreshToken` is a non-empty string (Refresh Token Rotation), the cached value is replaced.
    // If `refreshToken` is `()` or an empty string (no rotation), the existing cached token is preserved.
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
            if refreshToken is string && refreshToken != "" {
                self.refreshToken = refreshToken;
            }
        }
    }
}
