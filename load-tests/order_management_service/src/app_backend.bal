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

import ballerina/http;

listener http:Listener appBackend = new (9090,
    secureSocket = {
        key: {
            certFile: "./resources/app_backend/public.crt",
            keyFile: "./resources/app_backend/private.key"
        }
    }
);

final http:Client webClient = check new ("https://localhost:8080",
    secureSocket = {
        cert: "./resources/app_backend/public.crt"
    },
    auth = {
        tokenUrl: "https://wso2is-sts-service:9443/oauth2/token",
        clientId: "uDMwA4hKR9H3deeXxvNf4sSU0i4a",
        clientSecret: "8FOUOKUQfOp47pUfJCsPA5X4clga",
        scopes: ["customer"],
        clientConfig: {
            customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
            secureSocket: {
                disable: true
            }
        }
    }
);

isolated service /'order on appBackend {
    isolated resource function post .(@http:Payload json payload) returns json|error {
        return webClient->post("/order", payload);
    }
}
