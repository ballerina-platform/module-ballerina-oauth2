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

listener http:Listener apiGateway = new (8080,
    secureSocket = {
        key: {
            certFile: "./resources/api_gateway/public.crt",
            keyFile: "./resources/api_gateway/private.key"
        }
    }
);


@http:ServiceConfig {
    auth: [
        {
            oauth2IntrospectionConfig: {
                url: "https://wso2is-sts-service:9443/oauth2/introspect",
                clientConfig: {
                    customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
                    secureSocket: {
                        disable: true
                    }
                }
            },
            scopes: ["customer"]
        }
    ]
}
isolated service /'order on apiGateway {
    isolated resource function post .(@http:Payload json payload) returns json {
        return payload;
    }
}
