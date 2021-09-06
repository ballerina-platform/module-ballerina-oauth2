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

listener http:Listener apiGateway = new (9090,
    secureSocket = {
        key: {
            certFile: "./resources/public.crt",
            keyFile: "./resources/private.key"
        }
    }
);


@http:ServiceConfig {
    auth: [
        {
            oauth2IntrospectionConfig: {
                url: "https://localhost:9443/oauth2/introspect",
                clientConfig: {
                    customHeaders: {"Authorization": "Basic YWRtaW46YWRtaW4="},
                    secureSocket: {
                        cert: "./resources/sts-public.crt"
                    }
                }
            },
            scopes: ["customer"]
        }
    ]
}
service /'order on apiGateway {
    resource function get [string orderId]() returns json|error {
        // We need to call the 'Order Service' via mTLS. For this guide, since we are not interested of the security of
        // rest of the components, we will be returning a success mock response.
        return {
            id: "100500",
            name: "Sample order",
            items: [
                {
                    category: "electronics",
                    code: "SOWH1000XM4",
                    qty: 2
                },
                {
                    category: "books",
                    code: "978-1617295959",
                    qty: 1
                }
            ]
        };
    }
}
