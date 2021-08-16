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
import ballerina/lang.runtime as runtime;

// ---------------- CLIENT CREDENTIALS GRANT TYPE ----------------

// Test the client credentials grant type with valid credentials
@test:Config {}
isolated function testClientCredentialsGrantType1() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
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
@test:Config {}
isolated function testClientCredentialsGrantType2() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "invalid_client_id",
        clientSecret: "invalid_client_secret",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the client credentials grant type with valid client-id and invalid client-secret
@test:Config {}
isolated function testClientCredentialsGrantType3() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "invalid_client_secret",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Client credentials are invalid.\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Client credentials are invalid.\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the client credentials grant type with empty client-id and client-secret
@test:Config {}
isolated function testClientCredentialsGrantType4() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: "",
        clientSecret: "",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the client credentials grant type with valid credentials
@test:Config {}
isolated function testClientCredentialsGrantType5() {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:9445/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
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

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will be
    // reissued by the provided refresh configurations.
    runtime:sleep(5.0);

    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// ---------------- PASSWORD GRANT TYPE ----------------

// Test the password grant type with valid credentials
@test:Config {}
isolated function testPasswordGrantType1() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
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
@test:Config {}
isolated function testPasswordGrantType2() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9445/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        refreshConfig: {
            refreshUrl: "https://localhost:9445/oauth2/token",
            scopes: ["view-order"],
            optionalParams: {
                "client": "ballerina"
            },
            clientConfig: {
                secureSocket: {
                   cert: {
                       path: TRUSTSTORE_PATH,
                       password: "ballerina"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
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

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will get
    // refreshed by the provided refresh configurations.
    runtime:sleep(5.0);

    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with an invalid username, password, and a valid refresh config
@test:Config {}
isolated function testPasswordGrantType3() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "invalid_username",
        password: "invalid_password",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        refreshConfig: {
            refreshUrl: "https://localhost:9443/oauth2/token",
            scopes: ["view-order"],
            optionalParams: {
                "client": "ballerina"
            },
            clientConfig: {
                secureSocket: {
                   cert: WSO2_PUBLIC_CERT_PATH
                }
            }
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Authentication failed for invalid_username\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Authentication failed for invalid_username\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with an valid username, password, and empty client-id and client-secret
@test:Config {}
isolated function testPasswordGrantType4() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "",
        clientSecret: "",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with an valid username, password, and without client-id and client-secret
@test:Config {}
isolated function testPasswordGrantType5() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        username: "admin",
        password: "admin",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with an valid username, password, and without client-id and client-secret
@test:Config {}
isolated function testPasswordGrantType6() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9445/oauth2/token",
        username: "admin",
        password: "admin",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        refreshConfig: {
            refreshUrl: "https://localhost:9445/oauth2/token",
            scopes: ["view-order"],
            optionalParams: {
                "client": "ballerina"
            },
            clientConfig: {
                secureSocket: {
                   cert: {
                       path: TRUSTSTORE_PATH,
                       password: "ballerina"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error\":\"invalid_client\", \"error_description\":\"Client authentication failed due to unknown client.\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the password grant type with valid credentials and without refresh config
@test:Config {}
isolated function testPasswordGrantType7() {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9445/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
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

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will get
    // refreshed. However, if the refresh configurations are not provided, it will be failed.
    runtime:sleep(5.0);

    response = provider.generateToken();
    if (response is Error) {
        assertContains(response, "Failed to refresh access token since refresh configurations are not provided.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// ---------------- REFRESH TOKEN GRANT TYPE ----------------

// Test the refresh token grant type with an invalid refresh token
@test:Config {}
isolated function testRefreshTokenGrantType1() {
    RefreshTokenGrantConfig config = {
        refreshUrl: "https://localhost:9443/oauth2/token",
        refreshToken: "invalid_refresh_token",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Persisted access token data not found\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the refresh token grant type with an valid configurations
@test:Config {}
isolated function testRefreshTokenGrantType2() {
    RefreshTokenGrantConfig config = {
        refreshUrl: "https://localhost:9445/oauth2/token",
        refreshToken: "24f19603-8565-4b5f-a036-88a945e1f272",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
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

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will be
    // refreshed again by the provided refresh configurations.
    runtime:sleep(5.0);

    response = provider.generateToken();
    if (response is string) {
        assertToken(response);
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the refresh token grant type with empty client-id and client-secret
@test:Config {}
isolated function testRefreshTokenGrantType3() {
    RefreshTokenGrantConfig config = {
        refreshUrl: "https://localhost:9443/oauth2/token",
        refreshToken: "24f19603-8565-4b5f-a036-88a945e1f272",
        clientId: "",
        clientSecret: "",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// ---------------- JWT BEARER GRANT TYPE ----------------

// Test the JWT bearer grant type with an valid JWT
@test:Config {}
isolated function testJwtBearerGrantType1() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NDQ0NzI2MjksICJuYm" +
                 "YiOjE2MjkxMTI2MjksICJpYXQiOjE2MjkxMTI2Mjl9.Qbi5kElPZlyViUUuYW9Ik4nXSeTIroacEDs4BoI0rAGAOBXfyWLW4Yx" +
                 "m6hAlb4GXtkPZ4YMO8c0mUgdXgvPVFqFYJuINNPu6Y_nExahAVD0VxCYRE59lEjRv7t_gqn5OxSu_jTGcgcHH8_j-tvL_-AHaq" +
                 "gflr5UljbTPtnQyXtLaPNeu3r7FoWs-LrewMPIm1aw5qc2gI2iYwI1jfIdpNlEjU6r_Mg6ou2D2AGqJa0QYN1FMqi4YJt2jHr6" +
                 "0tQMQIWJ7zhKU4ShZESxYOVKK_cBOeL6K-A07pNEZYaSxtCU3609MIZ8EOUJuQUJb7zHHxG4QziHM8eBwFo26yovBFw";
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: jwt,
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
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

// Test the JWT bearer grant type with an valid JWT (different issuer)
@test:Config {}
isolated function testJwtBearerGrantType2() {
    string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxN" +
                 "TE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: jwt,
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Internal Server Error.\",\"error\":\"server_error\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the JWT bearer grant type with an invalid assertion
@test:Config {}
isolated function testJwtBearerGrantType3() {
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: "invalid-assertion",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Error while parsing the JWT.\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the JWT bearer grant type with empty client-id and client-secret
@test:Config {}
isolated function testJwtBearerGrantType4() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NDQ0NzI2MjksICJuYm" +
                 "YiOjE2MjkxMTI2MjksICJpYXQiOjE2MjkxMTI2Mjl9.Qbi5kElPZlyViUUuYW9Ik4nXSeTIroacEDs4BoI0rAGAOBXfyWLW4Yx" +
                 "m6hAlb4GXtkPZ4YMO8c0mUgdXgvPVFqFYJuINNPu6Y_nExahAVD0VxCYRE59lEjRv7t_gqn5OxSu_jTGcgcHH8_j-tvL_-AHaq" +
                 "gflr5UljbTPtnQyXtLaPNeu3r7FoWs-LrewMPIm1aw5qc2gI2iYwI1jfIdpNlEjU6r_Mg6ou2D2AGqJa0QYN1FMqi4YJt2jHr6" +
                 "0tQMQIWJ7zhKU4ShZESxYOVKK_cBOeL6K-A07pNEZYaSxtCU3609MIZ8EOUJuQUJb7zHHxG4QziHM8eBwFo26yovBFw";
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: jwt,
        clientId: "",
        clientSecret: "",
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

// Test the JWT bearer grant type with an valid JWT, and without client-id and client-secret
@test:Config {}
isolated function testJwtBearerGrantType5() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NDQ0NzI2MjksICJuYm" +
                 "YiOjE2MjkxMTI2MjksICJpYXQiOjE2MjkxMTI2Mjl9.Qbi5kElPZlyViUUuYW9Ik4nXSeTIroacEDs4BoI0rAGAOBXfyWLW4Yx" +
                 "m6hAlb4GXtkPZ4YMO8c0mUgdXgvPVFqFYJuINNPu6Y_nExahAVD0VxCYRE59lEjRv7t_gqn5OxSu_jTGcgcHH8_j-tvL_-AHaq" +
                 "gflr5UljbTPtnQyXtLaPNeu3r7FoWs-LrewMPIm1aw5qc2gI2iYwI1jfIdpNlEjU6r_Mg6ou2D2AGqJa0QYN1FMqi4YJt2jHr6" +
                 "0tQMQIWJ7zhKU4ShZESxYOVKK_cBOeL6K-A07pNEZYaSxtCU3609MIZ8EOUJuQUJb7zHHxG4QziHM8eBwFo26yovBFw";
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: jwt,
        scopes: ["view-order"],
        optionalParams: {
            "client": "ballerina"
        },
        clientConfig: {
            secureSocket: {
               cert: WSO2_PUBLIC_CERT_PATH
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new(config);
    if (provider is error) {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}
