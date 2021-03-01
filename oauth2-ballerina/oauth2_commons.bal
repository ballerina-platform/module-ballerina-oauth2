// Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/crypto;
import ballerina/jballerina.java;

# Represents the configurations of the client used to call the introspection endpoint.
#
# + httpVersion - The HTTP version of the client
# + customHeaders - The list of custom HTTP headers
# + customPayload - The list of custom HTTP payload parameters
# + auth - The client auth configurations
# + secureSocket - SSL/TLS related configurations
public type ClientConfiguration record {|
    HttpVersion httpVersion = HTTP_1_1;
    map<string> customHeaders?;
    string customPayload?;
    ClientAuth auth?;
    SecureSocket secureSocket?;
|};

# Defines the authentication configuration types for the HTTP client used for token introspection.
public type ClientAuth ClientCredentialsGrantConfig|PasswordGrantConfig|DirectTokenConfig;

# Represents HTTP versions.
public enum HttpVersion {
    HTTP_1_1,
    HTTP_2
}

# Represents the SSL/TLS configurations.
#
# + disable - Disable SSL validation
# + trustStore - Configurations associated with TrustStore
public type SecureSocket record {|
    boolean disable = false;
    crypto:TrustStore trustStore?;
|};

# Represents HTTP versions.
public enum CredentialBearer {
    AUTH_HEADER_BEARER,
    POST_BODY_BEARER
}

isolated function doHttpRequest(string url, ClientConfiguration clientConfig, map<string> headers, string payload)
                                returns string|Error = @java:Method {
    'class: "org.ballerinalang.stdlib.oauth2.OAuth2Client"
} external;
