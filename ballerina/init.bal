// Copyright (c) 2020 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import ballerina/jballerina.java;

# Represents the default connection timeout values for the oauth2 client.
public const decimal DEFAULT_CONNECT_TIMEOUT = 15;

# Represents the default request timeout value for the oauth2 client.
public const decimal DEFAULT_REQ_TIMEOUT = 30;

# Represents the maximum time(in seconds) to wait for a connection to be established with the oauth2 endpoint.
# Defaults to 15 seconds. This is a global configuration which will be applied to all the internal oauth2 client calls.
public configurable decimal globalConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

# Represents the maximum time(in seconds) to wait for a response before the oauth2 endpoint request times out.
# Defaults to 30 seconds. This is a global configuration which will be applied to all the internal oauth2 client calls.
public configurable decimal globalReqTimeout = DEFAULT_REQ_TIMEOUT;

isolated function init() returns error? {
    setModule();
    check setOauth2ConnectionTimeout(globalConnectTimeout);
    check setOauth2RequestTimeout(globalReqTimeout);
}

isolated function setModule() = @java:Method {
    'class: "io.ballerina.stdlib.oauth2.ModuleUtils"
} external;

isolated function setOauth2ConnectionTimeout(decimal timeout) returns error? = @java:Method {
    'class: "io.ballerina.stdlib.oauth2.ModuleUtils"
} external;

isolated function setOauth2RequestTimeout(decimal timeout) returns error? = @java:Method {
    'class: "io.ballerina.stdlib.oauth2.ModuleUtils"
} external;
