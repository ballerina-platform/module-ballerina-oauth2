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

import io.ballerina.runtime.api.creators.ErrorCreator;
import io.ballerina.runtime.api.utils.StringUtils;
import io.ballerina.runtime.api.values.BError;
import io.ballerina.runtime.api.values.BMap;
import io.ballerina.runtime.api.values.BString;
import io.ballerina.stdlib.crypto.nativeimpl.Decode;

import java.util.Optional;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import static java.lang.System.err;

/**
 * Extern function to call identity provider endpoints like token endpoint, introspection endpoint, using the
 * JDK11 HttpClient and return the payload of the HTTP response.
 */
public class OAuth2Client {

    private OAuth2Client() {}

    public static Object doHttpRequest(BString url, BMap<BString, Object> clientConfig, BMap<BString, BString> headers,
                                       BString payload) {
        BString customPayload = getBStringValueIfPresent(clientConfig, OAuth2Constants.CUSTOM_PAYLOAD);
        String textPayload = payload.getValue();
        if (customPayload != null) {
            textPayload += "&" + customPayload;
        }

        ArrayList<String> headersList = new ArrayList<>();
        for (Map.Entry<BString, BString> entry : headers.entrySet()) {
            headersList.add(entry.getKey().getValue());
            headersList.add(entry.getValue().getValue());
        }

        Optional<BMap<BString, ?>> customHeaders = getBMapValueIfPresent(clientConfig, OAuth2Constants.CUSTOM_HEADERS);
        customHeaders.ifPresent( customHeaders -> {
            for (Map.Entry<BString, ?> entry : customHeaders.entrySet()) {
                headersList.add(entry.getKey().getValue());
                headersList.add(((BString) entry.getValue()).getValue());
            }
        });

        String httpVersion = getBStringValueIfPresent(clientConfig, OAuth2Constants.HTTP_VERSION).getValue();
        Optional<BMap<BString, ?>> secureSocket = getBMapValueIfPresent(clientConfig, OAuth2Constants.SECURE_SOCKET);

        HttpRequest request;
        URI uri;
        try {
            uri = buildUri(url.getValue(), secureSocket);
        } catch (IllegalArgumentException e) {
            return createError("Failed to create URI for the provided value \"" + url + "\".");
        }

        if (headersList.isEmpty()) {
            request = buildHttpRequest(uri, textPayload);
        } else {
            String[] flatHeaders = headersList.toArray(String[]::new);
            request = buildHttpRequest(uri, flatHeaders, textPayload);
        }
        if (secureSocket.isPresent()) {
            try {
                SSLContext sslContext = getSslContext(secureSocket.get());
                HttpClient client = buildHttpClient(httpVersion, sslContext);
                return callEndpoint(client, request);
            } catch (Exception e) {
                return createError("Failed to init SSL context. " + e.getMessage());
            }
        }        
        HttpClient client = buildHttpClient(httpVersion);
        return callEndpoint(client, request);
    }

    private static URI buildUri(String url, Optional<BMap<BString, ?>> secureSocket) throws IllegalArgumentException {
        String[] urlParts = url.split(OAuth2Constants.SCHEME_SEPARATOR, 2);
        if (urlParts.length == 1) {
            urlParts = secureSocket.isPresent() ? new String[]{OAuth2Constants.HTTPS_SCHEME, urlParts[0]} :
                    new String[]{OAuth2Constants.HTTP_SCHEME, urlParts[0]};
        } else if (urlParts[0].equals(OAuth2Constants.HTTP_SCHEME) && secureSocket.isPresent()){
            err.println(OAuth2Constants.RUNTIME_WARNING_PREFIX + OAuth2Constants.HTTPS_RECOMMENDATION_ERROR);
        }
        urlParts[1] = urlParts[1].replaceAll(OAuth2Constants.DOUBLE_SLASH, OAuth2Constants.SINGLE_SLASH);
        url = urlParts[0] + OAuth2Constants.SCHEME_SEPARATOR + urlParts[1];
        return URI.create(url);
    }

    private static SSLContext getSslContext(BMap<BString, ?> secureSocket) throws Exception {
        boolean disable = secureSocket.getBooleanValue(OAuth2Constants.DISABLE);
        if (disable) {
            return initSslContext();
        }
        Optional<BMap<BString, BString>> key = Optional.ofNullable(getBMapValueIfPresent(secureSocket, OAuth2Constants.KEY));
        Object cert = secureSocket.get(OAuth2Constants.CERT);
        if (cert == null) {
            throw new Exception("Need to configure 'crypto:TrustStore' or 'cert' with client SSL certificates file.");
        }
        KeyManagerFactory kmf = null;
        TrustManagerFactory tmf = null;
        if (cert instanceof BString) {
            if (key.isPresent()) {
                tmf = getTrustManagerFactory((BString) cert);
                if (key.get().containsKey(OAuth2Constants.CERT_FILE)) {
                    BString certFile = key.get().get(OAuth2Constants.CERT_FILE);
                    BString keyFile = key.get().get(OAuth2Constants.KEY_FILE);
                    BString keyPassword = getBStringValueIfPresent(key.get(), OAuth2Constants.KEY_PASSWORD);
                    kmf = getKeyManagerFactory(certFile, keyFile, keyPassword);
                    return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
                }
                kmf = getKeyManagerFactory(key.get());
                return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
            }            
            tmf = getTrustManagerFactory((BString) cert);
            return buildSslContext(null, tmf.getTrustManagers());
        }
        if (cert instanceof BMap) {
            BMap<BString, BString> trustStore = (BMap<BString, BString>) cert;
            if(key.isPresent()){
                tmf = getTrustManagerFactory(trustStore);
                if (key.get().containsKey(OAuth2Constants.CERT_FILE)) {
                    BString certFile = key.get(OAuth2Constants.CERT_FILE);
                    BString keyFile = key.get(OAuth2Constants.KEY_FILE);
                    BString keyPassword = getBStringValueIfPresent(key, OAuth2Constants.KEY_PASSWORD);
                    kmf = getKeyManagerFactory(certFile, keyFile, keyPassword);
                    return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
                }
                kmf = getKeyManagerFactory(key.get());
                return buildSslContext(kmf.getKeyManagers(), tmf.getTrustManagers());
            }
            return buildSslContext(null, tmf.getTrustManagers());
        }
        throw new Exception("Failed to initialize SSLContext.");
    }

    private static HttpClient.Version getHttpVersion(String httpVersion) {
        if (OAuth2Constants.HTTP_2.equals(httpVersion)) {
            return HttpClient.Version.HTTP_2;
        }
        return HttpClient.Version.HTTP_1_1;
    }

    private static SSLContext initSslContext() throws Exception {
        TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
        };
        return buildSslContext(null, trustManagers);
    }

    private static TrustManagerFactory getTrustManagerFactory(BString cert) throws Exception {
        Object publicKeyMap = Decode.decodeRsaPublicKeyFromCertFile(cert);
        if (publicKeyMap instanceof BMap) {
            X509Certificate x509Certificate = (X509Certificate) ((BMap<BString, Object>) publicKeyMap).getNativeData(
                    OAuth2Constants.NATIVE_DATA_PUBLIC_KEY_CERTIFICATE);
            KeyStore ts = KeyStore.getInstance(OAuth2Constants.PKCS12);
            ts.load(null, "".toCharArray());
            ts.setCertificateEntry(UUID.randomUUID().toString(), x509Certificate);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ts);
            return tmf;
        }
        throw new Exception("Failed to get the public key from Crypto API. " +
                            ((BError) publicKeyMap).getErrorMessage().getValue());
    }

    private static TrustManagerFactory getTrustManagerFactory(BMap<BString, BString> trustStore) throws Exception {
        BString trustStorePath = trustStore.getStringValue(OAuth2Constants.PATH);
        BString trustStorePassword = trustStore.getStringValue(OAuth2Constants.PASSWORD);
        KeyStore ts = getKeyStore(trustStorePath, trustStorePassword);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        return tmf;
    }

    private static KeyManagerFactory getKeyManagerFactory(BMap<BString, BString> keyStore) throws Exception {
        BString keyStorePath = keyStore.getStringValue(OAuth2Constants.PATH);
        BString keyStorePassword = keyStore.getStringValue(OAuth2Constants.PASSWORD);
        KeyStore ks = getKeyStore(keyStorePath, keyStorePassword);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyStorePassword.getValue().toCharArray());
        return kmf;
    }

    private static KeyManagerFactory getKeyManagerFactory(BString certFile, BString keyFile, BString keyPassword)
            throws Exception {
        Object publicKey = Decode.decodeRsaPublicKeyFromCertFile(certFile);
        if (publicKey instanceof BMap) {
            X509Certificate publicCert = (X509Certificate) ((BMap<BString, Object>) publicKey).getNativeData(
                    OAuth2Constants.NATIVE_DATA_PUBLIC_KEY_CERTIFICATE);
            Object privateKeyMap = Decode.decodeRsaPrivateKeyFromKeyFile(keyFile, keyPassword);
            if (privateKeyMap instanceof BMap) {
                PrivateKey privateKey = (PrivateKey) ((BMap<BString, Object>) privateKeyMap).getNativeData(
                        OAuth2Constants.NATIVE_DATA_PRIVATE_KEY);
                KeyStore ks = KeyStore.getInstance(OAuth2Constants.PKCS12);
                ks.load(null, "".toCharArray());
                ks.setKeyEntry(UUID.randomUUID().toString(), privateKey, "".toCharArray(),
                               new X509Certificate[]{publicCert});
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, "".toCharArray());
                return kmf;
            }
        }
        throw new Exception("Failed to get the public key from Crypto API. " +
                                    ((BError) publicKey).getErrorMessage().getValue());
    }

    private static KeyStore getKeyStore(BString path, BString password) throws Exception {
        try (FileInputStream is = new FileInputStream(path.getValue())) {
            char[] passphrase = password.getValue().toCharArray();
            KeyStore ks = KeyStore.getInstance(OAuth2Constants.PKCS12);
            ks.load(is, passphrase);
            return ks;
        }
    }

    private static SSLContext buildSslContext(KeyManager[] keyManagers, TrustManager[] trustManagers) throws Exception {
        SSLContext sslContext = SSLContext.getInstance(OAuth2Constants.TLS);
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return sslContext;
    }

    private static HttpClient buildHttpClient(String httpVersion) {
        return HttpClient.newBuilder().version(getHttpVersion(httpVersion)).build();
    }

    private static HttpClient buildHttpClient(String httpVersion, SSLContext sslContext) {
        return HttpClient.newBuilder().version(getHttpVersion(httpVersion)).sslContext(sslContext).build();
    }

    private static HttpRequest buildHttpRequest(URI uri, String payload) {
        return HttpRequest.newBuilder()
                .uri(uri)
                .setHeader(OAuth2Constants.CONTENT_TYPE, OAuth2Constants.APPLICATION_FORM_URLENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
    }

    private static HttpRequest buildHttpRequest(URI uri, String[] headers, String payload) {
        return HttpRequest.newBuilder()
                .uri(uri)
                .headers(headers)
                .setHeader(OAuth2Constants.CONTENT_TYPE, OAuth2Constants.APPLICATION_FORM_URLENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();
    }

    private static Object callEndpoint(HttpClient client, HttpRequest request) {
        try {
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                return StringUtils.fromString(response.body());
            }
            return createError("Failed to get a success response from the endpoint. Response code: '" +
                                       response.statusCode() + "'. Response body: '" + response.body() + "'");
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt(); // Restore interrupted status
            }
            return createError("Failed to send the request to the endpoint. " + e.getMessage());
        }
    }

    private static BMap<BString, ?> getBMapValueIfPresent(BMap<BString, ?> config, BString key) {
        return config.containsKey(key) ? (BMap<BString, ?>) config.getMapValue(key) : null;
    }

    private static BString getBStringValueIfPresent(BMap<BString, ?> config, BString key) {
        return config.containsKey(key) ? config.getStringValue(key) : null;
    }

    private static BError createError(String errMsg) {
        return ErrorCreator.createError(ModuleUtils.getModule(), OAuth2Constants.OAUTH2_ERROR_TYPE,
                                        StringUtils.fromString(errMsg), null, null);
    }
}
