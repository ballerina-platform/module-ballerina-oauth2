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

// Test the client credentials grant type with valid credentials
@test:Config {
    groups: ["provider"]
}
isolated function testClientCredentialsGrantType1() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider provider = new(config);
    string|Error response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the client credentials grant type with invalid client credentials
@test:Config {
    groups: ["provider"]
}
isolated function testClientCredentialsGrantType2() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "invalid_client_id",
        clientSecret: "invalid_client_secret",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "A valid OAuth client could not be found for client_id: invalid_client_id");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "A valid OAuth client could not be found for client_id: invalid_client_id");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the client credentials grant type with valid client id and invalid client secret
@test:Config {
    groups: ["provider"]
}
isolated function testClientCredentialsGrantType3() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "invalid_client_secret",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client Authentication failed.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client Authentication failed.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with valid credentials
@test:Config {
    groups: ["provider"]
}
isolated function testPasswordGrantType1() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider provider = new(config);
    string|Error response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with valid credentials and a valid refresh config
@test:Config {
    groups: ["provider"]
}
isolated function testPasswordGrantType2() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        refreshConfig: {
            refreshUrl: "https://localhost:9443/oauth2/token",
            scopes: ["view-order"],
            clientConfig: {
                secureSocket: {
                   cert: {
                       path: WSO2_TRUSTSTORE_PATH,
                       password: "wso2carbon"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider provider = new(config);
    string|Error response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with an invalid username, password, and a valid refresh config
@test:Config {
    groups: ["provider"]
}
isolated function testPasswordGrantType3() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "invalid_username",
        password: "invalid_password",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        refreshConfig: {
            refreshUrl: "https://localhost:9443/oauth2/token",
            scopes: ["view-order"],
            clientConfig: {
                secureSocket: {
                   cert: {
                       path: WSO2_TRUSTSTORE_PATH,
                       password: "wso2carbon"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Authentication failed for invalid_username");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Authentication failed for invalid_username");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {
    groups: ["provider"]
}
isolated function testDirectToken1() {
    // Test the direct token mode with an invalid access token and a valid refresh config
    DirectTokenConfig config = {
        refreshUrl: "https://localhost:9443/oauth2/token",
        refreshToken: "invalid_refresh_token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
               cert: {
                   path: WSO2_TRUSTSTORE_PATH,
                   password: "wso2carbon"
               }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Persisted access token data not found");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}
