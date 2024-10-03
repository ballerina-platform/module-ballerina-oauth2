// Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/cache;
import ballerina/log;
import ballerina/time;

# Represents the introspection endpoint configurations.
#
# + url - URL of the introspection endpoint
# + tokenTypeHint - A hint about the type of the token submitted for introspection
# + optionalParams - Map of the optional parameters used for the introspection endpoint
# + cacheConfig - Configurations for the cache used to store the OAuth2 access token and other related information
# + defaultTokenExpTime - Expiration time (in seconds) of the tokens if the introspection response does not contain an `exp` field
# + clientConfig - HTTP client configurations, which call the introspection endpoint
public type IntrospectionConfig record {
    string url;
    string tokenTypeHint?;
    map<string> optionalParams?;
    cache:CacheConfig cacheConfig?;
    decimal defaultTokenExpTime = 3600;
    ClientConfiguration clientConfig = {};
};

# Represents the introspection endpoint response.
#
# + active - Boolean indicator of whether or not the presented token is currently active
# + scope - A JSON string containing a space-separated list of scopes associated with this token
# + clientId - Client identifier for the OAuth 2.0 client, which requested this token
# + username - Resource owner who authorized this token
# + tokenType - Type of the token
# + exp - Expiry time (seconds since the Epoch)
# + iat - Time when the token was issued originally (seconds since the Epoch)
# + nbf - Token is not to be used before this time (seconds since the Epoch)
# + sub - Subject of the token
# + aud - Intended audience of the token
# + iss - Issuer of the token
# + jti - String identifier for the token
public type IntrospectionResponse record {
    boolean active;
    string scope?;
    string clientId?;
    string username?;
    string tokenType?;
    int exp?;
    int iat?;
    int nbf?;
    string sub?;
    string aud?;
    string iss?;
    string jti?;
};

// IntrospectionResponse parameters
const string ACTIVE = "active";
const string SCOPE = "scope";
const string CLIENT_ID = "client_id";
const string USERNAME = "username";
const string TOKEN_TYPE = "token_type";
const string EXP = "exp";
const string IAT = "iat";
const string NBF = "nbf";
const string SUB = "sub";
const string AUD = "aud";
const string ISS = "iss";
const string JTI = "jti";

# Represents the listener OAuth2 provider, which is used to validate the received credential (access token) by
# calling the configured introspection endpoint.
# ```ballerina
# oauth2:IntrospectionConfig config = {
#     url: "https://localhost:9196/oauth2/token/introspect"
# };
# oauth2:ListenerOAuth2Provider provider = new(config);
# ```
public isolated class ListenerOAuth2Provider {

    private final IntrospectionConfig & readonly introspectionConfig;
    private final cache:Cache? oauth2Cache;
    private final ClientOAuth2Provider? clientOAuth2Provider;

    # Provides authorization based on the provided introspection configurations.
    #
    # + introspectionConfig - Introspection endpoint configurations
    public isolated function init(IntrospectionConfig introspectionConfig) {
        self.introspectionConfig = introspectionConfig.cloneReadOnly();
        cache:CacheConfig? oauth2CacheConfig = introspectionConfig?.cacheConfig;
        if oauth2CacheConfig is cache:CacheConfig {
            self.oauth2Cache = new(oauth2CacheConfig);
        } else {
            self.oauth2Cache = ();
        }
        ClientAuth? auth = introspectionConfig.clientConfig?.auth;
        if auth is ClientAuth {
            self.clientOAuth2Provider = new(auth);
        } else {
            self.clientOAuth2Provider = ();
        }
    }

    # Validates the provided OAuth2 acess token against the introspection endpoint.
    # ```ballerina
    # boolean result = check provider.authorize("<credential>");
    # ```
    #
    # + credential - OAuth2 access token to be validated
    # + optionalParams - Map of the optional parameters used for the introspection endpoint
    # + return - An `oauth2:IntrospectionResponse` if the validation is successful or else an `oauth2:Error` if an error occurred
    public isolated function authorize(string credential, map<string>? optionalParams = ()) returns IntrospectionResponse|Error {
        if credential == "" {
            return prepareError("Credential cannot be empty.");
        }

        cache:Cache? oauth2Cache = self.oauth2Cache;
        if oauth2Cache is cache:Cache && oauth2Cache.hasKey(credential) {
            IntrospectionResponse? response = validateFromCache(oauth2Cache, credential);
            if response is IntrospectionResponse {
                return response;
            }
        }
        IntrospectionResponse|Error validationResult = validate(credential, self.introspectionConfig,
                                                                self.clientOAuth2Provider, optionalParams);
        if validationResult is IntrospectionResponse {
            if oauth2Cache is cache:Cache {
                addToCache(oauth2Cache, credential, validationResult, self.introspectionConfig.defaultTokenExpTime);
            }
            return validationResult;
        } else {
            return prepareError("OAuth2 validation failed.", validationResult);
        }
    }
}

// Validates the provided OAuth2 access token by calling the introspection endpoint.
isolated function validate(string token, IntrospectionConfig config, ClientOAuth2Provider? clientOAuth2Provider,
                           map<string>? optionalParams) returns IntrospectionResponse|Error {
    // Builds the request to be sent to the introspection endpoint. For more information, see the
    // [OAuth 2.0 Token Introspection RFC](https://tools.ietf.org/html/rfc7662#section-2.1)
    string textPayload = "token=" + token;
    string? tokenTypeHint = config?.tokenTypeHint;
    if tokenTypeHint is string {
        textPayload += "&token_type_hint=" + tokenTypeHint;
    }
    map<string>? configOptionalParams = config?.optionalParams;
    if configOptionalParams is map<string> {
        foreach [string, string] [key, value] in configOptionalParams.entries() {
            textPayload = textPayload + "&" + key.trim() + "=" + value.trim();
        }
    }
    if optionalParams is map<string> {
        foreach [string, string] [key, value] in optionalParams.entries() {
            textPayload = textPayload + "&" + key.trim() + "=" + value.trim();
        }
    }
    map<string> customHeadersMap = {};
    ClientOAuth2Provider? oauth2Provider = clientOAuth2Provider;
    if oauth2Provider is ClientOAuth2Provider {
        string|Error accessToken = oauth2Provider.generateToken();
        if accessToken is string {
            customHeadersMap["Authorization"] = "Bearer " + accessToken;
        }
    }
    string|Error stringResponse = doHttpRequest(config.url, config.clientConfig, customHeadersMap, textPayload);
    if stringResponse is string {
        json|error jsonResponse = stringResponse.fromJsonString();
        if jsonResponse is json {
            return prepareIntrospectionResponse(jsonResponse);
        } else {
            return prepareError("Failed to convert '" + stringResponse + "' to JSON.", jsonResponse);
        }
    } else {
        return prepareError("Failed to call the introspection endpoint '" + config.url + "'.", stringResponse);
    }
}

isolated function prepareIntrospectionResponse(json payload) returns IntrospectionResponse {
    IntrospectionResponse introspectionResponse = {
        active: false
    };
    map<json> payloadMap = <map<json>>payload;
    string[] keys = payloadMap.keys();
    foreach string key in keys {
        match key {
            ACTIVE => {
                introspectionResponse.active = <boolean>payloadMap[key];
            }
            SCOPE => {
                introspectionResponse.scope = <string>payloadMap[key];
            }
            CLIENT_ID => {
                introspectionResponse.clientId = <string>payloadMap[key];
            }
            USERNAME => {
                introspectionResponse.username = <string>payloadMap[key];
            }
            TOKEN_TYPE => {
                introspectionResponse.tokenType = <string>payloadMap[key];
            }
            EXP => {
                introspectionResponse.exp = parseExpClaim(payloadMap[key]);
            }
            IAT => {
                introspectionResponse.iat = <int>payloadMap[key];
            }
            NBF => {
                introspectionResponse.nbf = <int>payloadMap[key];
            }
            SUB => {
                introspectionResponse.sub = <string>payloadMap[key];
            }
            AUD => {
                introspectionResponse.aud = <string>payloadMap[key];
            }
            ISS => {
                introspectionResponse.iss = <string>payloadMap[key];
            }
            JTI => {
                introspectionResponse.jti = <string>payloadMap[key];
            }
            _ => {
                introspectionResponse[key] = payloadMap[key];
            }
        }
    }
    return introspectionResponse;
}

isolated function addToCache(cache:Cache oauth2Cache, string token, IntrospectionResponse response,
        decimal defaultTokenExpTime) {
    cache:Error? result;
    if response?.exp is int {
        result = oauth2Cache.put(token, response);
    } else {
        // If the `exp` parameter is not set by the introspection response, use the cache default expiry by
        // the `defaultTokenExpTime`. Then, the cached value will be removed when retrieving.
        result = oauth2Cache.put(token, response, defaultTokenExpTime);
    }
    if result is cache:Error {
        log:printDebug("Failed to add OAuth2 access token to the cache.", 'error = result);
    }
}

isolated function validateFromCache(cache:Cache oauth2Cache, string token) returns IntrospectionResponse? {
    any|cache:Error cachedEntry = oauth2Cache.get(token);
    if cachedEntry is () {
        // If the cached value is expired (defaultTokenExpTime is passed), it will return `()`.
        return;
    }
    if cachedEntry is any {
        IntrospectionResponse response = <IntrospectionResponse>cachedEntry;
        int? expTime = response?.exp;
        // The `expTime` can be `()`. This means that the `defaultTokenExpTime` is not exceeded yet.
        // Hence, the token is still valid. If the `expTime` is provided in int, convert this to the current time and
        // check if the expiry time is exceeded.
        [int, decimal] currentTime = time:utcNow();
        if expTime is () || expTime > currentTime[0] {
            return response;
        }
        cache:Error? result = oauth2Cache.invalidate(token);
        if result is cache:Error {
            log:printDebug("Failed to invalidate OAuth2 access token from the cache.", 'error = result);
        }
    } else {
        log:printDebug("Failed to validate the token from the cache.", 'error = cachedEntry);
    }
    return;
}

isolated function parseExpClaim(json expClaim) returns int|() {
    if expClaim is string {
        return checkpanic int:fromString(expClaim);
    } 
    return <int>expClaim;
}
