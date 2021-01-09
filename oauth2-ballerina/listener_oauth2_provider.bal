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
import ballerina/stringutils;
import ballerina/time;

# Represents the introspection server configurations.
#
# + url - URL of the introspection server
# + tokenTypeHint - A hint about the type of the token submitted for introspection
# + cacheConfig - Configurations for the cache used to store the OAuth2 token and other related information
# + defaultTokenExpTimeInSeconds - Expiration time of the tokens if introspection response does not contain an `exp` field
# + clientConfig - HTTP client configurations which calls the introspection server
public type IntrospectionConfig record {
    string url;
    string tokenTypeHint?;
    cache:CacheConfig cacheConfig?;
    int defaultTokenExpTimeInSeconds = 3600;
    ClientConfiguration clientConfig = {};
};

# Represents the introspection server response.
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

# Represents the inbound OAuth2 provider, which calls the introspection server, validates the received credentials,
# and performs authentication and authorization.
# ```ballerina
# oauth2:IntrospectionConfig config = {
#     url: "https://localhost:9196/oauth2/token/introspect"
# };
# oauth2:ListenerOAuth2Provider provider = new(config);
# ```
public class ListenerOAuth2Provider {

    IntrospectionConfig introspectionConfig;
    cache:Cache? oauth2Cache = ();

    # Provides authentication based on the provided introspection configurations.
    #
    # + introspectionConfig - OAuth2 introspection server configurations
    public isolated function init(IntrospectionConfig introspectionConfig) {
        self.introspectionConfig = introspectionConfig;
        cache:CacheConfig? oauth2CacheConfig = introspectionConfig?.cacheConfig;
        if (oauth2CacheConfig is cache:CacheConfig) {
            self.oauth2Cache = new(oauth2CacheConfig);
        }
    }

    # Authenticates the provider OAuth2 tokens with an introspection endpoint.
    # ```ballerina
    # boolean|oauth2:Error result = provider.authenticate("<credential>");
    # ```
    #
    # + credential - OAuth2 token to be authenticated
    # + return - `oauth2:IntrospectionResponse` if authentication is successful, or else an `oauth2:Error` if an error occurred
    public isolated function authorize(string credential) returns IntrospectionResponse|Error {
        if (credential == "") {
            return prepareError("Credential cannot be empty.");
        }

        cache:Cache? oauth2Cache = self.oauth2Cache;
        if (oauth2Cache is cache:Cache && oauth2Cache.hasKey(credential)) {
            IntrospectionResponse? response = validateFromCache(oauth2Cache, credential);
            if (response is IntrospectionResponse) {
                return response;
            }
        }

        IntrospectionResponse|Error validationResult = validate(credential, self.introspectionConfig);
        if (validationResult is Error) {
            return prepareError("OAuth2 validation failed.", validationResult);
        }
        if (oauth2Cache is cache:Cache) {
            addToCache(oauth2Cache, credential, checkpanic validationResult,
                       self.introspectionConfig.defaultTokenExpTimeInSeconds);
        }
        return checkpanic validationResult;
    }
}

//# Validates the provided OAuth2 token by calling the OAuth2 introspection endpoint.
//# ```ballerina
//# oauth2:IntrospectionResponse|oauth2:Error result = oauth2:validate(token, introspectionServerConfig);
//# ```
//#
//# + token - OAuth2 token, which needs to be validated
//# + config -  OAuth2 introspection server configurations
//# + return - OAuth2 introspection server response or else an `oauth2:Error` if token validation fails
isolated function validate(string token, IntrospectionConfig config) returns IntrospectionResponse|Error {
    // Builds the request to be sent to the introspection endpoint. For more information, refer to the
    // [OAuth 2.0 Token Introspection RFC](https://tools.ietf.org/html/rfc7662#section-2.1)
    string textPayload = "token=" + token;
    string? tokenTypeHint = config?.tokenTypeHint;
    if (tokenTypeHint is string) {
        textPayload += "&token_type_hint=" + tokenTypeHint;
    }
    string|Error stringResponse = doHttpRequest(config.url, config.clientConfig, {}, textPayload);
    if (stringResponse is Error) {
        return prepareError("Failed to call introspection endpoint.", stringResponse);
    }
    json|error jsonResponse = (checkpanic stringResponse).fromJsonString();
    if (jsonResponse is error) {
        return prepareError(jsonResponse.message(), jsonResponse);
    }
    return prepareIntrospectionResponse(checkpanic jsonResponse);
}

isolated function prepareIntrospectionResponse(json payload) returns IntrospectionResponse {
    IntrospectionResponse introspectionResponse = {
        active: false
    };
    map<json> payloadMap = <map<json>>payload;
    string[] keys = payloadMap.keys();
    foreach string key in keys {
        match (key) {
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
                introspectionResponse.exp = <int>payloadMap[key];
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
                introspectionResponse[key] = payloadMap[key].toJsonString();
            }
        }
    }
    return introspectionResponse;
}

isolated function addToCache(cache:Cache oauth2Cache, string token, IntrospectionResponse response,
                             int defaultTokenExpTimeInSeconds) {
    cache:Error? result;
    if (response?.exp is int) {
        result = oauth2Cache.put(token, response);
    } else {
        // If the `exp` parameter is not set by the introspection response, use the cache default expiry by
        // the `defaultTokenExpTimeInSeconds`. Then, the cached value will be removed when retrieving.
        result = oauth2Cache.put(token, response, defaultTokenExpTimeInSeconds);
    }
    if (result is cache:Error) {
        log:printError("Failed to add OAuth2 token to the cache. Introspection response: " + response.toString());
        return;
    }
}

isolated function validateFromCache(cache:Cache oauth2Cache, string token) returns IntrospectionResponse? {
    any|cache:Error cachedEntry = oauth2Cache.get(token);
    if (cachedEntry is ()) {
        // If the cached value is expired (defaultTokenExpTimeInSeconds is passed), it will return `()`.
        return;
    }
    if (cachedEntry is cache:Error) {
        log:printError("Failed to validate the token from the cache. Cache error: " + cachedEntry.toString());
        return;
    }
    IntrospectionResponse response = <IntrospectionResponse> checkpanic cachedEntry;
    int? expTime = response?.exp;
    // The `expTime` can be `()`. This means that the `defaultTokenExpTimeInSeconds` is not exceeded yet.
    // Hence, the token is still valid. If the `expTime` is provided in int, convert this to the current time and
    // check if the expiry time is exceeded.
    if (expTime is () || expTime > (time:currentTime().time / 1000)) {
        return response;
    } else {
        cache:Error? result = oauth2Cache.invalidate(token);
        if (result is cache:Error) {
            log:printError("Failed to invalidate OAuth2 token from the cache. Introspection response: " + response.toString());
        }
    }
}

isolated function getScopes(string? scopes) returns string[] {
    if (scopes is ()) {
        return [];
    } else {
        string scopeVal = scopes.trim();
        if (scopeVal == "") {
            return [];
        }
        return stringutils:split(scopeVal, " ");
    }
}
