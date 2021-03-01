// Copyright (c) 2021 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

// NOTE: All the tokens/credentials used in this test are dummy tokens/credentials and used only for testing purposes.

import ballerina/test;

isolated function getAccessToken() returns string {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider provider = new(config);
    return checkpanic provider.generateToken();
}

// Test the introspection request with successful token
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer1() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is IntrospectionResponse) {
        test:assertTrue(response.active);
        test:assertEquals(response?.scope, "view-order");
        test:assertEquals(response?.clientId, "FlfJYKBD2c925h4lkycqNZlC2l4a");
        test:assertEquals(response?.username, "admin@carbon.super");
        test:assertEquals(response?.tokenType, "Bearer");
        test:assertTrue(response?.exp is int);
        test:assertTrue(response?.iat is int);
        test:assertTrue(response?.nbf is int);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with invalid token
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer2() {
    string accessToken = "invalid_token";
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is IntrospectionResponse) {
        test:assertFalse(response.active);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with successful token without authenticating the client
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer3() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is Error) {
        assertContains(response, "Failed to get a success response from the endpoint. Response Code: '401'.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with successful token with valid OAuth2 client credentials grant type
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer4() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            auth: {
                tokenUrl: "https://localhost:9443/oauth2/token",
                clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
                clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
                clientConfig: {
                    secureSocket: {
                       trustStore: {
                           path: WSO2_TRUSTSTORE_PATH,
                           password: "wso2carbon"
                       }
                    }
                }
            },
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is IntrospectionResponse) {
        test:assertTrue(response.active);
        test:assertEquals(response?.scope, "view-order");
        test:assertEquals(response?.clientId, "FlfJYKBD2c925h4lkycqNZlC2l4a");
        test:assertEquals(response?.username, "admin@carbon.super");
        test:assertEquals(response?.tokenType, "Bearer");
        test:assertTrue(response?.exp is int);
        test:assertTrue(response?.iat is int);
        test:assertTrue(response?.nbf is int);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with successful token with valid OAuth2 password grant type
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer5() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            auth: {
                tokenUrl: "https://localhost:9443/oauth2/token",
                username: "admin",
                password: "admin",
                clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
                clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
                scopes: ["view-order"],
                clientConfig: {
                    secureSocket: {
                       trustStore: {
                           path: WSO2_TRUSTSTORE_PATH,
                           password: "wso2carbon"
                       }
                    }
                }
            },
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is IntrospectionResponse) {
        test:assertTrue(response.active);
        test:assertEquals(response?.scope, "view-order");
        test:assertEquals(response?.clientId, "FlfJYKBD2c925h4lkycqNZlC2l4a");
        test:assertEquals(response?.username, "admin@carbon.super");
        test:assertEquals(response?.tokenType, "Bearer");
        test:assertTrue(response?.exp is int);
        test:assertTrue(response?.iat is int);
        test:assertTrue(response?.nbf is int);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with successful token with invalid OAuth2 client credentials grant type
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer6() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            auth: {
                tokenUrl: "https://localhost:9443/oauth2/token",
                clientId: "invalid_client_id",
                clientSecret: "invalid_client_secret",
                clientConfig: {
                    secureSocket: {
                       trustStore: {
                           path: WSO2_TRUSTSTORE_PATH,
                           password: "wso2carbon"
                       }
                    }
                }
            },
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is Error) {
        assertContains(response, "Failed to get a success response from the endpoint. Response Code: '401'.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the introspection request with successful token with invalid OAuth2 password grant type
@test:Config {
    groups: ["provider"]
}
isolated function testIntrospectionServer7() {
    string accessToken = getAccessToken();
    IntrospectionConfig config = {
        url: "https://localhost:9443/oauth2/introspect",
        clientConfig: {
            auth: {
                tokenUrl: "https://localhost:9443/oauth2/token",
                username: "invalid_username",
                password: "invalid_password",
                clientId: "invalid_client_id",
                clientSecret: "invalid_client_secret",
                scopes: ["view-order"],
                clientConfig: {
                    secureSocket: {
                       trustStore: {
                           path: WSO2_TRUSTSTORE_PATH,
                           password: "wso2carbon"
                       }
                    }
                }
            },
            secureSocket: {
               trustStore: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ListenerOAuth2Provider provider = new(config);
    IntrospectionResponse|Error response = provider.authorize(accessToken);
    if (response is Error) {
        assertContains(response, "Failed to get a success response from the endpoint. Response Code: '401'.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}
