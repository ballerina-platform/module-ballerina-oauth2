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

import ballerina/regex;
import ballerina/test;

const string KEYSTORE_PATH = "tests/resources/keystore/ballerinaKeystore.p12";
const string TRUSTSTORE_PATH = "tests/resources/keystore/ballerinaTruststore.p12";
const string WSO2_KEYSTORE_PATH = "tests/resources/keystore/wso2Keystore.p12";
const string WSO2_TRUSTSTORE_PATH = "tests/resources/keystore/wso2Truststore.p12";
const string WSO2_PUBLIC_CERT = "tests/resources/cert/wso2Public.crt";

isolated function assertToken(string token) {
    string[] parts = regex:split(token, "-");
    test:assertEquals(parts.length(), 5);
    test:assertEquals(parts[0].length(), 8);
    test:assertEquals(parts[1].length(), 4);
    test:assertEquals(parts[2].length(), 4);
    test:assertEquals(parts[3].length(), 4);
    test:assertEquals(parts[4].length(), 12);
}

isolated function assertContains(Error err, string text) {
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
    test:assertTrue(message.includes(text));
}
