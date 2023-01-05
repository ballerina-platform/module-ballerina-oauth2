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
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testClientCredentialsGrantType1() returns Error? {
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);
}

// Test the client credentials grant type with invalid client credentials
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the client credentials grant type with valid client-id and invalid client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Client credentials are invalid.\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Client credentials are invalid.\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
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
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the client credentials grant type with valid credentials
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testClientCredentialsGrantType5() returns Error? {
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will be
    // reissued by the provided refresh configurations.
    runtime:sleep(5.0);

    response = check provider.generateToken();
    assertToken(response);
}

// ---------------- PASSWORD GRANT TYPE ----------------

// Test the password grant type with valid credentials
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testPasswordGrantType1() returns Error? {
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);
}

// Test the password grant type with valid credentials and a valid refresh config
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testPasswordGrantType2() returns Error? {
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will get
    // refreshed by the provided refresh configurations.
    runtime:sleep(5.0);

    response = check provider.generateToken();
    assertToken(response);
}

// Test the password grant type with an invalid username, password, and a valid refresh config
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Authentication failed for invalid_username\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Authentication failed for invalid_username\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail("Expected error not found.");
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
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the password grant type with an valid username, password, and without client-id and client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the password grant type with an valid username, password, and without client-id and client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error\":\"invalid_client\", \"error_description\":\"Client authentication failed due to unknown client.\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the password grant type with valid credentials and without refresh config
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testPasswordGrantType7() returns Error? {
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
    string response1 = check provider.generateToken();
    assertToken(response1);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will get
    // refreshed. However, if the refresh configurations are not provided, it will be failed.
    runtime:sleep(5.0);

    string|Error response2 = provider.generateToken();
    if response2 is Error {
        assertContains(response2, "Failed to refresh access token since refresh configurations are not provided.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the password grant type with valid credentials and refresh config
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testPasswordGrantType8() returns Error? {
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:9445/oauth2/token",
        username: "admin",
        password: "admin",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        refreshConfig: INFER_REFRESH_CONFIG,
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
    string response1 = check provider.generateToken();
    assertToken(response1);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will get
    // refreshed.
    runtime:sleep(5.0);

    string|Error response2 = check provider.generateToken();
    test:assertTrue(response2 is string, "Expected refresh token not found");
}

// ---------------- REFRESH TOKEN GRANT TYPE ----------------

// Test the refresh token grant type with an invalid refresh token
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Persisted access token data not found\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the refresh token grant type with an valid configurations
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testRefreshTokenGrantType2() returns Error? {
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will be
    // refreshed again by the provided refresh configurations.
    runtime:sleep(5.0);

    response = check provider.generateToken();
    assertToken(response);
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
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the refresh token grant type with invalid client-id and client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testRefreshTokenGrantType4() {
    RefreshTokenGrantConfig config = {
        refreshUrl: "https://localhost:9443/oauth2/token",
        refreshToken: "24f19603-8565-4b5f-a036-88a945e1f272",
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// ---------------- JWT BEARER GRANT TYPE ----------------

// Test the JWT bearer grant type with an valid JWT
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testJwtBearerGrantType1() returns Error? {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NTg2MTIwMjksICJuYm" +
                 "YiOjE2NDMyNTIwMjksICJpYXQiOjE2NDMyNTIwMjl9.MBjE6L8xu3QyuN9bjJfcg-yCAbmuPrqidWRRp0Gcu120_wIis7nmg7x" +
                 "Or8BW-6h8CQEswjIXyW5ULYk_y9d61zPNJlPbcTgJSHc2roPuBGoa3szHjd1G2eZE14SLsLUsbmz5_g1ZeOrqJxtKAholUENvN" +
                 "1xZtSw8jZwc_RMRA3xXaLvfoys0I6D-iQqrqjQ2CmCoZTkqTPDkoV8xRS4U4AGJgXJtRqfQeEPjJsnTSQpidMuElEnUnV_u6MZ" +
                 "hwhZVSNBbLZZpu8SPsyL-FHftd_VVGI6abrOFP4XZaRwVomyClme2q7zTH_H66Pkh_85J9_tj14cODY81J8Tbmloj7g";
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
    string response = check provider.generateToken();
    assertToken(response);

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = new(config);
    response = check provider.generateToken();
    assertToken(response);

    // The access token is valid only for 2 seconds. Wait 5 seconds and try again so that the access token will be
    // reissued by the provided configurations.
    runtime:sleep(5.0);

    response = check provider.generateToken();
    assertToken(response);
}

// Test the JWT bearer grant type with an valid JWT (different issuer)
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Internal Server Error.\",\"error\":\"server_error\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the JWT bearer grant type with an invalid assertion
@test:Config {
    groups: ["skipOnWindows"]
}
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Error while parsing the JWT.\",\"error\":\"invalid_grant\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the JWT bearer grant type with empty client-id and client-secret
@test:Config {}
isolated function testJwtBearerGrantType4() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NTg2MTIwMjksICJuYm" +
                 "YiOjE2NDMyNTIwMjksICJpYXQiOjE2NDMyNTIwMjl9.MBjE6L8xu3QyuN9bjJfcg-yCAbmuPrqidWRRp0Gcu120_wIis7nmg7x" +
                 "Or8BW-6h8CQEswjIXyW5ULYk_y9d61zPNJlPbcTgJSHc2roPuBGoa3szHjd1G2eZE14SLsLUsbmz5_g1ZeOrqJxtKAholUENvN" +
                 "1xZtSw8jZwc_RMRA3xXaLvfoys0I6D-iQqrqjQ2CmCoZTkqTPDkoV8xRS4U4AGJgXJtRqfQeEPjJsnTSQpidMuElEnUnV_u6MZ" +
                 "hwhZVSNBbLZZpu8SPsyL-FHftd_VVGI6abrOFP4XZaRwVomyClme2q7zTH_H66Pkh_85J9_tj14cODY81J8Tbmloj7g";
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
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "Client-id or client-secret cannot be empty.");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the JWT bearer grant type with an valid JWT, and without client-id and client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testJwtBearerGrantType5() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NTg2MTIwMjksICJuYm" +
                 "YiOjE2NDMyNTIwMjksICJpYXQiOjE2NDMyNTIwMjl9.MBjE6L8xu3QyuN9bjJfcg-yCAbmuPrqidWRRp0Gcu120_wIis7nmg7x" +
                 "Or8BW-6h8CQEswjIXyW5ULYk_y9d61zPNJlPbcTgJSHc2roPuBGoa3szHjd1G2eZE14SLsLUsbmz5_g1ZeOrqJxtKAholUENvN" +
                 "1xZtSw8jZwc_RMRA3xXaLvfoys0I6D-iQqrqjQ2CmCoZTkqTPDkoV8xRS4U4AGJgXJtRqfQeEPjJsnTSQpidMuElEnUnV_u6MZ" +
                 "hwhZVSNBbLZZpu8SPsyL-FHftd_VVGI6abrOFP4XZaRwVomyClme2q7zTH_H66Pkh_85J9_tj14cODY81J8Tbmloj7g";
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"Unsupported Client Authentication Method!\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

// Test the JWT bearer grant type with invalid client-id and client-secret
@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testJwtBearerGrantType6() {
    string jwt = "eyJhbGciOiJSUzI1NiIsICJ0eXAiOiJKV1QiLCAia2lkIjoiTXpZeE1tRmtPR1l3TVdJMFpXTm1ORGN4TkdZd1ltTTRaVEEzTV" +
                 "dJMk5EQXpaR1F6TkdNMFpHIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJzdWIiOiJh" +
                 "ZG1pbiIsICJhdWQiOiJodHRwczovL2xvY2FsaG9zdDo5NDQzL29hdXRoMi90b2tlbiIsICJleHAiOjE5NTg2MTIwMjksICJuYm" +
                 "YiOjE2NDMyNTIwMjksICJpYXQiOjE2NDMyNTIwMjl9.MBjE6L8xu3QyuN9bjJfcg-yCAbmuPrqidWRRp0Gcu120_wIis7nmg7x" +
                 "Or8BW-6h8CQEswjIXyW5ULYk_y9d61zPNJlPbcTgJSHc2roPuBGoa3szHjd1G2eZE14SLsLUsbmz5_g1ZeOrqJxtKAholUENvN" +
                 "1xZtSw8jZwc_RMRA3xXaLvfoys0I6D-iQqrqjQ2CmCoZTkqTPDkoV8xRS4U4AGJgXJtRqfQeEPjJsnTSQpidMuElEnUnV_u6MZ" +
                 "hwhZVSNBbLZZpu8SPsyL-FHftd_VVGI6abrOFP4XZaRwVomyClme2q7zTH_H66Pkh_85J9_tj14cODY81J8Tbmloj7g";
    JwtBearerGrantConfig config = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: jwt,
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
    if provider is error {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }

    // Send the credentials in request body
    config.credentialBearer = POST_BODY_BEARER;
    provider = trap new(config);
    if provider is error {
        assertContains(provider, "{\"error_description\":\"A valid OAuth client could not be found for client_id: invalid_client_id\",\"error\":\"invalid_client\"}");
    } else {
        test:assertFail("Expected error not found.");
    }
}

@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testAccessTokenRequestWithoutUrlScheme() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "localhost:9444/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"]
    };
    ClientOAuth2Provider provider = new(config);
    string response = check provider.generateToken();
    assertToken(response);
}

@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testAccessTokenRequestWithHttpUrlScheme() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "http://localhost:9444/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"]
    };
    ClientOAuth2Provider provider = new(config);
    string response = check provider.generateToken();
    assertToken(response);
}

@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testAccessTokenRequestWithSecureSocketAndWithoutUrlScheme() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "localhost:9445/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
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
    string response = check provider.generateToken();
    assertToken(response);
}

@test:Config {
    groups: ["skipOnWindows"]
}
isolated function testAccessTokenRequestWithSecureSocketAndWithHttpUrlScheme() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "http://localhost:9444/oauth2/token",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
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
    string response = check provider.generateToken();
    assertToken(response);
}

@test:Config {}
isolated function testInvalidTokenUrl() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
                cert: {
                    path: TRUSTSTORE_PATH,
                    password: "ballerina"
                }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new (config);
    if provider is Error {
        test:assertEquals(provider.message(), "Failed to call the token endpoint ''.");
        test:assertTrue(provider.cause() is Error);
        Error cause = <Error>provider.cause();
        test:assertEquals(cause.message(), "Failed to create URI for the provided value \"\".");
    } else {
        test:assertFail("The provider should be an oauth2:Error");
    }
}

@test:Config {}
isolated function testInvalidTokenUrl2() returns Error? {
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://abc d.com",
        clientId: "FlfJYKBD2c925h4lkycqNZlC2l4a",
        clientSecret: "PJz0UhTJMrHOo68QQNpvnqAY_3Aa",
        scopes: ["view-order"],
        clientConfig: {
            secureSocket: {
                cert: {
                    path: TRUSTSTORE_PATH,
                    password: "ballerina"
                }
            }
        }
    };
    ClientOAuth2Provider|error provider = trap new (config);
    if provider is Error {
        test:assertEquals(provider.message(), "Failed to call the token endpoint 'https://abc d.com'.");
        test:assertTrue(provider.cause() is Error);
        Error cause = <Error>provider.cause();
        test:assertEquals(cause.message(), "Failed to create URI for the provided value \"https://abc d.com\".");
    } else {
        test:assertFail("The provider should be an oauth2:Error");
    }
}
