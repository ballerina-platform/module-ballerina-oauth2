// Copyright (c) 2018 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import ballerina/auth;
import ballerina/stringutils;

@test:Config {}
public function testClientCredentialsGrantType1() {
    // Test the client credentials grant type with valid credentials
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/header",
        clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
        clientSecret: "9205371918321623741",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "3XR8L5KXwE/EjBv+PjqCqA==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testClientCredentialsGrantType2() {
    // Test the client credentials grant type with invalid client credentials
    ClientCredentialsGrantConfig config = {
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/header",
        clientId: "invalid_client_id",
        clientSecret: "invalid_client_secret",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is auth:Error) {
        assertContains(response, "invalid_client");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testClientCredentialsGrantType3() {
    // Test the client credentials grant type with a post-body bearer and valid credentials
    ClientCredentialsGrantConfig config = {
        credentialBearer: POST_BODY_BEARER,
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/body",
        clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
        clientSecret: "9205371918321623741",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "3XR8L5KXwE/EjBv+PjqCqA==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testClientCredentialsGrantType4() {
    // Test the client credentials grant type with a post-body bearer and invalid credentials
    ClientCredentialsGrantConfig config = {
        credentialBearer: POST_BODY_BEARER,
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/body",
        clientId: "invalid_client_id",
        clientSecret: "invalid_client_secret",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is auth:Error) {
        assertContains(response, "invalid_client");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testPasswordGrantType1() {
    // Test the password grant type with valid credentials
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/header",
        username: "johndoe",
        password: "A3ddj3w",
        clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
        clientSecret: "9205371918321623741",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "qTjCiM6LkCmEs3GyCrEq/Q==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testPasswordGrantType2() {
    // Test the password grant type with valid credentials and a valid refresh config
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/header",
        username: "johndoe",
        password: "A3ddj3w",
        clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
        clientSecret: "9205371918321623741",
        scopes: ["token-scope1", "token-scope2"],
        refreshConfig: {
            refreshUrl: "https://localhost:20299/oauth2/token/refresh",
            scopes: ["token-scope1", "token-scope2"],
            clientConfig: {
                secureSocket: {
                   trustStore: {
                       path: TRUSTSTORE_PATH,
                       password: "ballerina"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "qTjCiM6LkCmEs3GyCrEq/Q==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testPasswordGrantType3() {
    // Test the password grant type with an invalid username, password, and a valid refresh config
    PasswordGrantConfig config = {
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/header",
        username: "invalid_username",
        password: "invalid_password",
        clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
        clientSecret: "9205371918321623741",
        scopes: ["token-scope1", "token-scope2"],
        refreshConfig: {
            refreshUrl: "https://localhost:20299/oauth2/token/refresh",
            scopes: ["token-scope1", "token-scope2"],
            clientConfig: {
                secureSocket: {
                   trustStore: {
                       path: TRUSTSTORE_PATH,
                       password: "ballerina"
                   }
                }
            }
        },
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is auth:Error) {
        assertContains(response, "unauthorized_client");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testPasswordGrantType4() {
    // Test the password grant type with a bearer without credentials and a valid username and password
    PasswordGrantConfig config = {
        credentialBearer: NO_BEARER,
        tokenUrl: "https://localhost:20299/oauth2/token/authorize/none",
        username: "johndoe",
        password: "A3ddj3w",
        scopes: ["token-scope1", "token-scope2"],
        clientConfig: {
            secureSocket: {
               trustStore: {
                   path: TRUSTSTORE_PATH,
                   password: "ballerina"
               }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "JoalArhmyx8Hac7PcNYwfQ==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

@test:Config {}
public function testDirectToken1() {
    // Test the direct token mode with valid credentials and without a refresh config
    DirectTokenConfig config = {
        accessToken: "2YotnFZFEjr1zCsicMWpAA"
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "2YotnFZFEjr1zCsicMWpAA");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

//@test:Config {}
//public function testDirectToken2() {
//    // Test the direct token mode with an invalid access token and without a refresh config
//    DirectTokenConfig config = {
//        accessToken: "invalid_access_token"
//    };
//    OutboundOAuth2Provider provider = new(config);
//    string|auth:Error response = provider.generateToken();
//    if (response is auth:Error) {
//        assertContains(response, "Failed to refresh access token since DirectRefreshTokenConfig is not provided.");
//    } else {
//        test:assertFail(msg = "Test Failed! ");
//    }
//}

@test:Config {}
public function testDirectToken3() {
    // Test the direct token mode with an invalid access token and a valid refresh config
    DirectTokenConfig config = {
        refreshConfig: {
            refreshUrl: "https://localhost:20299/oauth2/token/refresh",
            refreshToken: "XlfBs91yquexJqDaKEMzVg==",
            clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
            clientSecret: "9205371918321623741",
            scopes: ["token-scope1", "token-scope2"],
            clientConfig: {
                secureSocket: {
                   trustStore: {
                       path: TRUSTSTORE_PATH,
                       password: "ballerina"
                   }
                }
            }
        }
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "eXs9rJcluGXJTxhJ5sybAg==");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

//@test:Config {}
//public function testDirectToken4() {
//    // Test the direct token mode (with the retrying request set as false) with an invalid access token and without a refresh config
//    DirectTokenConfig config = {
//        accessToken: "invalid_access_token",
//        retryRequest: false
//    };
//    OutboundOAuth2Provider provider = new(config);
//    string|auth:Error response = provider.generateToken();
//    if (response is auth:Error) {
//        assertContains(response, "Failed to get the access token since retry request is set as false.");
//    } else {
//        test:assertFail(msg = "Test Failed! ");
//    }
//}

//@test:Config {}
//public function testDirectToken5() {
//    // Test the direct token mode (with the retrying request set as false) with an invalid access token and a valid refresh config
//    DirectTokenConfig config = {
//        accessToken: "invalid_access_token",
//        retryRequest: false,
//        refreshConfig: {
//            refreshUrl: "https://localhost:20299/oauth2/token/refresh",
//            refreshToken: "XlfBs91yquexJqDaKEMzVg==",
//            clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
//            clientSecret: "9205371918321623741",
//            scopes: ["token-scope1", "token-scope2"],
//            clientConfig: {
//                secureSocket: {
//                   trustStore: {
//                       path: TRUSTSTORE_PATH,
//                       password: "ballerina"
//                   }
//                }
//            }
//        }
//    };
//    OutboundOAuth2Provider provider = new(config);
//    string|auth:Error response = provider.generateToken();
//    if (response is auth:Error) {
//        assertContains(response, "Failed to get the access token since retry request is set as false.");
//    } else {
//        test:assertFail(msg = "Test Failed! ");
//    }
//}

//@test:Config {}
//public function testDirectToken6() {
//    // Test the direct token mode with an invalid access token and an invalid refresh config
//    DirectTokenConfig config = {
//        accessToken: "invalid_access_token",
//        refreshConfig: {
//            refreshUrl: "https://localhost:20299/oauth2/token/refresh",
//            refreshToken: "invalid_refresh_token",
//            clientId: "3MVG9YDQS5WtC11paU2WcQjBB3L5w4gz52uriT8ksZ3nUVjKvrfQMrU4uvZohTftxStwNEW4cfStBEGRxRL68",
//            clientSecret: "9205371918321623741",
//            scopes: ["token-scope1", "token-scope2"],
//            clientConfig: {
//                secureSocket: {
//                   trustStore: {
//                       path: TRUSTSTORE_PATH,
//                       password: "ballerina"
//                   }
//                }
//            }
//        }
//    };
//    OutboundOAuth2Provider provider = new(config);
//    string|auth:Error response = provider.generateToken();
//    if (response is string) {
//        test:assertEquals(response, "JoalArhmyx8Hac7PcNYwfQ==");
//        //assertContains(response, "invalid_grant");
//    } else {
//        test:assertFail(msg = "Test Failed! ");
//    }
//}

@test:Config {}
public function testDirectToken7() {
    // Test the direct token mode with valid credentials (with the retrying request set as false) and without a refresh config
    DirectTokenConfig config = {
        accessToken: "2YotnFZFEjr1zCsicMWpAA",
        retryRequest: false
    };
    OutboundOAuth2Provider provider = new(config);
    string|auth:Error response = provider.generateToken();
    if (response is string) {
        test:assertEquals(response, "2YotnFZFEjr1zCsicMWpAA");
    } else {
        test:assertFail(msg = "Test Failed! ");
    }
}

function assertContains(auth:Error err, string text) {
    string message = err.message();
    var cause = err.cause();
    if (cause is error) {
        var innerCause = cause.cause();
        while (innerCause is error) {
            cause = innerCause;
            innerCause = innerCause.cause();
        }
        message = cause.message();
    }
    test:assertTrue(stringutils:contains(message, text));
}
