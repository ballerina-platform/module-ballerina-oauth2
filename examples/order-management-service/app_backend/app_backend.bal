// Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import ballerina/http;

configurable string clientId = ?;
configurable string clientSecret = ?;

listener http:Listener appBackend = new (8080,
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);

final http:Client webClient = check new ("https://localhost:9090",
    secureSocket = {
        cert: "./resources/public.crt"
    },
    auth = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        clientId: clientId,
        clientSecret: clientSecret,
        scopes: ["customer"],
        clientConfig: {
            customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
            secureSocket: {
                cert: "./resources/sts-public.crt"
            }
        }
    }
);

final http:Client mobileClient = check new ("https://localhost:9090",
    secureSocket = {
        cert: "./resources/public.crt"
    },
    auth = {
        tokenUrl: "https://localhost:9443/oauth2/token",
        assertion: idToken,
        clientId: clientId,
        clientSecret: clientSecret,
        scopes: ["customer"],
        clientConfig: {
            customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
            secureSocket: {
                cert: "./resources/sts-public.crt"
            }
        }
    }
);

service /'order on appBackend {
    resource function get web(string orderId) returns json|error {
        return webClient->get("/order/" + orderId);
    }

    resource function get mobile(string orderId, string idToken) returns json|error {
        return mobileClient->get("/order/" + orderId);
    }
}
