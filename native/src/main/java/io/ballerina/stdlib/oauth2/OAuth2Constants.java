/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.ballerina.stdlib.oauth2;

import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BString;

/**
 * Constants related to Ballerina OAuth2 stdlib.
 */
public class OAuth2Constants {

    private OAuth2Constants() {}

    public static final String OAUTH2_ERROR_TYPE = "Error";

    public static final String SINGLE_SLASH = "/";
    public static final String DOUBLE_SLASH = "//";
    public static final String SCHEME_SEPARATOR = "://";
    public static final String HTTP_SCHEME = "http";
    public static final String HTTPS_SCHEME = "https";

    public static final BString HTTP_VERSION = StringUtils.fromString("httpVersion");
    public static final BString SECURE_SOCKET = StringUtils.fromString("secureSocket");
    public static final BString DISABLE = StringUtils.fromString("disable");
    public static final BString CERT = StringUtils.fromString("cert");
    public static final BString KEY = StringUtils.fromString("key");
    public static final BString CERT_FILE = StringUtils.fromString("certFile");
    public static final BString KEY_FILE = StringUtils.fromString("keyFile");
    public static final BString KEY_PASSWORD = StringUtils.fromString("keyPassword");
    public static final BString PATH = StringUtils.fromString("path");
    public static final BString PASSWORD = StringUtils.fromString("password");
    public static final BString CUSTOM_HEADERS = StringUtils.fromString("customHeaders");
    public static final BString CUSTOM_PAYLOAD = StringUtils.fromString("customPayload");
    public static final BString CONNECTION_TIMEOUT = StringUtils.fromString("connectTimeout");
    public static final BString REQUEST_TIMEOUT = StringUtils.fromString("reqTimeout");

    public static final String TLS = "TLS";
    public static final String PKCS12 = "PKCS12";
    public static final String HTTP_2 = "HTTP_2";

    public static final String CONTENT_TYPE = "Content-Type";
    public static final String APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded";

    public static final String NATIVE_DATA_PUBLIC_KEY_CERTIFICATE = "NATIVE_DATA_PUBLIC_KEY_CERTIFICATE";
    public static final String NATIVE_DATA_PRIVATE_KEY = "NATIVE_DATA_PRIVATE_KEY";

    public static final String RUNTIME_WARNING_PREFIX = "warning: [ballerina/oauth2] ";
    public static final String HTTPS_RECOMMENDATION_ERROR = "HTTPS is recommended but using HTTP";
}
