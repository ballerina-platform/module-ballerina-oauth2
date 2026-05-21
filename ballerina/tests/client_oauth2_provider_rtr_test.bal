// Copyright (c) 2024 WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
//
// WSO2 LLC. licenses this file to you under the Apache License,
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

// Unit tests for Refresh Token Rotation (RTR) behavior in TokenCache.
// These tests exercise the cache directly without any network calls.

import ballerina/test;
import ballerina/lang.runtime as runtime;

// When the server returns a new refresh_token, it replaces the cached one.
@test:Config {}
isolated function testTokenCacheRtrUpdatesRefreshToken() {
    TokenCache cache = new;
    cache.update("AT1", "RT1", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");

    cache.update("AT2", "RT2", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");

    cache.update("AT3", "RT3", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT3");
}

// When the server does NOT return a refresh_token, the existing cached one is preserved.
@test:Config {}
isolated function testTokenCacheRtrPreservesRefreshTokenWhenAbsent() {
    TokenCache cache = new;
    cache.update("AT1", "RT1", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");

    cache.update("AT2", (), 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");

    cache.update("AT3", (), 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");
}

// Five consecutive rotations: each refresh must use the latest rotated refresh token.
@test:Config {}
isolated function testTokenCacheSequentialRtrRotations() {
    TokenCache cache = new;
    string[] refreshTokens = ["RT1", "RT2", "RT3", "RT4", "RT5"];
    string[] accessTokens = ["AT1", "AT2", "AT3", "AT4", "AT5"];

    foreach int i in 0 ..< refreshTokens.length() {
        cache.update(accessTokens[i], refreshTokens[i], 10, 3600, 0);
        test:assertEquals(cache.getRefreshToken(), refreshTokens[i]);
        test:assertEquals(cache.getAccessToken(), accessTokens[i]);
    }
}

// Empty cache forces fallback to config.refreshToken in refresh functions.
@test:Config {}
isolated function testTokenCacheInitialState() {
    TokenCache cache = new;
    test:assertEquals(cache.getRefreshToken(), "");
    test:assertEquals(cache.getAccessToken(), "");
    test:assertTrue(cache.isAccessTokenExpired());
}

// Access token expiry does not clear the stored refresh token.
@test:Config {}
isolated function testTokenCacheExpiryWithRtr() {
    TokenCache cache = new;
    cache.update("AT1", "RT1", 1, 3600, 0);

    test:assertEquals(cache.getAccessToken(), "AT1");
    test:assertEquals(cache.getRefreshToken(), "RT1");
    test:assertFalse(cache.isAccessTokenExpired());

    runtime:sleep(2.0);

    test:assertTrue(cache.isAccessTokenExpired());
    test:assertEquals(cache.getRefreshToken(), "RT1");
}

// Alternating rotate / no-rotate sequences: last rotated token is always preserved.
@test:Config {}
isolated function testTokenCacheRtrMixedRotations() {
    TokenCache cache = new;

    cache.update("AT1", "RT1", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");

    cache.update("AT2", "RT2", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");

    // Server does not rotate this time — RT2 must be preserved.
    cache.update("AT3", (), 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");

    // Server does not rotate again — RT2 still preserved.
    cache.update("AT4", (), 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");

    // Server rotates again.
    cache.update("AT5", "RT3", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT3");
}

// ─── extractRefreshToken() unit tests ────────────────────────────────────────

// refresh_token present and non-empty → returned as-is.
@test:Config {}
isolated function testExtractRefreshTokenWhenPresent() {
    json response = {"access_token": "AT1", "refresh_token": "RT1", "expires_in": 3600};
    string? rt = extractRefreshToken(response);
    test:assertEquals(rt, "RT1");
}

// refresh_token field absent → nil returned, existing cache must not be touched.
@test:Config {}
isolated function testExtractRefreshTokenWhenAbsent() {
    json response = {"access_token": "AT1", "expires_in": 3600};
    string? rt = extractRefreshToken(response);
    test:assertTrue(rt is (), "Expected nil when refresh_token is absent");
}

// refresh_token present but not a string (e.g. integer) → nil returned.
@test:Config {}
isolated function testExtractRefreshTokenWhenNotString() {
    json response = {"access_token": "AT1", "refresh_token": 12345};
    string? rt = extractRefreshToken(response);
    test:assertTrue(rt is (), "Expected nil when refresh_token is not a string");
}

// refresh_token present but empty string → nil returned (must NOT overwrite cached token).
@test:Config {}
isolated function testExtractRefreshTokenWhenEmptyString() {
    json response = {"access_token": "AT1", "refresh_token": ""};
    string? rt = extractRefreshToken(response);
    test:assertTrue(rt is (), "Expected nil when refresh_token is an empty string");
}

// Empty JSON object → nil returned.
@test:Config {}
isolated function testExtractRefreshTokenFromEmptyResponse() {
    json response = {};
    string? rt = extractRefreshToken(response);
    test:assertTrue(rt is (), "Expected nil from empty response");
}

// ─── TokenCache empty-string defense tests ────────────────────────────────────

// update() with empty-string refresh token must NOT overwrite the existing cached RT.
// This guards against servers that return "refresh_token": "" which would otherwise
// silently clear the rotation chain.
@test:Config {}
isolated function testTokenCacheRtrIgnoresEmptyStringUpdate() {
    TokenCache cache = new;
    cache.update("AT1", "RT1", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1");

    // Simulate a server returning an empty-string refresh_token.
    cache.update("AT2", "", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT1", "Cached RT must not be cleared by empty-string update");
    test:assertEquals(cache.getAccessToken(), "AT2", "Access token must still be updated");
}

// update() with empty-string on initially empty cache leaves cache empty.
@test:Config {}
isolated function testTokenCacheRtrEmptyStringOnEmptyCache() {
    TokenCache cache = new;
    cache.update("AT1", "", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "", "Empty cache must remain empty after empty-string update");
    test:assertEquals(cache.getAccessToken(), "AT1");
}

// ─── Config seed pattern tests ────────────────────────────────────────────────

// Initially the cache is empty (getRefreshToken() == "").
// This empty state is exactly what triggers the config.refreshToken fallback in the production code.
// After the first successful update with a real RT, the cache is non-empty and config is no longer used.
@test:Config {}
isolated function testTokenCacheConfigSeedPattern() {
    TokenCache cache = new;

    // Phase 1: empty cache → production code would use config.refreshToken as the seed.
    string beforeSeed = cache.getRefreshToken();
    test:assertEquals(beforeSeed, "");

    // Phase 2: first successful refresh — server returns AT1 + RT1.
    cache.update("AT1", "RT1", 10, 3600, 0);
    string afterSeed = cache.getRefreshToken();
    test:assertNotEquals(afterSeed, "", "Cache must be non-empty after first update");
    test:assertEquals(afterSeed, "RT1");

    // Phase 3: from this point, production code uses "RT1" from cache, NOT config.refreshToken.
    // A second rotation (server returns RT2) replaces RT1.
    cache.update("AT2", "RT2", 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");

    // Phase 4: no rotation (server returns no RT) — RT2 is preserved, config still not used.
    cache.update("AT3", (), 10, 3600, 0);
    test:assertEquals(cache.getRefreshToken(), "RT2");
}

// ─── Error resilience: cache is unchanged when update() is never called ──────

// When the HTTP refresh call fails, the error is propagated via `check` and update() is never
// invoked. This test verifies that the TokenCache remains in its last-known-good state, so the
// next generateToken() call can retry using the same refresh token.
@test:Config {}
isolated function testTokenCacheUnchangedWhenUpdateNotCalled() {
    TokenCache cache = new;
    cache.update("AT1", "RT1", 1, 3600, 0);

    runtime:sleep(2.0); // AT1 is now expired

    // Confirm the access token is expired but the refresh token is still available.
    test:assertTrue(cache.isAccessTokenExpired());
    test:assertEquals(cache.getRefreshToken(), "RT1",
        "Refresh token must survive access token expiry and be available for retry");

    // If a refresh attempt were to fail here (network error, invalid grant, etc.),
    // update() is never called, so the cache still holds RT1 for the next retry.
    test:assertEquals(cache.getAccessToken(), "AT1",
        "Stale access token stays in cache until update() is called on success");
}
