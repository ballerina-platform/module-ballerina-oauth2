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

import io.ballerina.runtime.api.Environment;
import io.ballerina.runtime.api.Module;
import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BDecimal;

/**
 * Utility functions relevant to module operations.
 *
 * @since 2.0.0
 */
public class ModuleUtils {

    private static Module oauth2Module;
    private static double oauth2ConnectionTimeout = 15.0;
    private static double oauth2RequestTimeout = 30.0;

    private ModuleUtils() {}

    public static void setModule(Environment env) {
        oauth2Module = env.getCurrentModule();
    }

    public static Module getModule() {
        return oauth2Module;
    }

    public static Object setOauth2ConnectionTimeout(BDecimal timeout) {
        double doubleValue = timeout.floatValue();
        if (doubleValue <= 0) {
            String errMsg = "OAuth2 connection timeout must be greater than zero";
            return ErrorCreator.createError(ModuleUtils.getModule(), OAuth2Constants.OAUTH2_ERROR_TYPE,
                    StringUtils.fromString(errMsg), null, null);
        }
        oauth2ConnectionTimeout = doubleValue;
        return null;
    }

    public static double getOauth2ConnectionTimeout() {
        return oauth2ConnectionTimeout;
    }

    public static Object setOauth2RequestTimeout(BDecimal timeout) {
        double doubleValue = timeout.floatValue();
        if (doubleValue <= 0) {
            String errMsg = "OAuth2 request timeout must be greater than zero";
            return ErrorCreator.createError(ModuleUtils.getModule(), OAuth2Constants.OAUTH2_ERROR_TYPE,
                    StringUtils.fromString(errMsg), null, null);
        }
        oauth2RequestTimeout = doubleValue;
        return null;
    }

    public static double getOauth2RequestTimeout() {
        return oauth2RequestTimeout;
    }
}
