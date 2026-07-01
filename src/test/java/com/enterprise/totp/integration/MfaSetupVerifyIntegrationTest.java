package com.enterprise.totp.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class MfaSetupVerifyIntegrationTest {

    @LocalServerPort
    private int port;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CodeGenerator codeGenerator = new DefaultCodeGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    private String baseUrl() {
        return "http://localhost:" + port + "/api/v1/mfa";
    }

    // ---------- Test 1: Setup success ----------
    @Test
    void setup_shouldReturnOtpauthUri_forNewUser() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        HttpResponse<String> response = callSetup(userId);

        assertEquals(201, response.statusCode()); // setup creates a resource -> 201
        assertTrue(response.body().contains("otpauth://totp/"));
        assertTrue(response.body().contains("secret="));
    }

    // ---------- Test 2: Setup conflict (already enabled) ----------
    @Test
    void setup_shouldReturn409_whenAlreadyEnabled() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        callSetup(userId); // first setup - succeeds

        HttpResponse<String> secondResponse = callSetup(userId); // duplicate

        assertEquals(409, secondResponse.statusCode());
        assertTrue(secondResponse.body().contains("mfa-already-enabled"));
    }

    // ---------- Test 3: Verify success with valid code ----------
    @Test
    void verify_shouldReturn200_withValidFreshCode() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        String otpauthUri = extractOtpauthUri(callSetup(userId));
        String code = generateCodeFromUri(otpauthUri);

        HttpResponse<String> response = callVerify(userId, code);

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"verified\":true"));
    }

    // ---------- Test 4: Verify fails with wrong code ----------
    @Test
    void verify_shouldReturn401_withInvalidCode() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        callSetup(userId);

        HttpResponse<String> response = callVerify(userId, "000000");

        assertEquals(401, response.statusCode());
    }

    // ---------- Test 5: Verify fails for non-existent user ----------
    @Test
    void verify_shouldReturn401_whenUserNotFound() throws Exception {
        HttpResponse<String> response = callVerify("nonexistent_" + UUID.randomUUID(), "123456");

        assertEquals(401, response.statusCode());
    }

    // ---------- Test 6: Replay attack - same code twice ----------
    @Test
    void verify_shouldReject_replayedCode() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        String otpauthUri = extractOtpauthUri(callSetup(userId));
        String code = generateCodeFromUri(otpauthUri);

        HttpResponse<String> firstAttempt = callVerify(userId, code);
        assertEquals(200, firstAttempt.statusCode());

        HttpResponse<String> secondAttempt = callVerify(userId, code); // same code again
        assertEquals(401, secondAttempt.statusCode());
    }

    // ---------- Test 7: Verify fails with malformed code (not 6 digits) ----------
    @Test
    void verify_shouldReturn400_forMalformedCode() throws Exception {
        String userId = "test_" + UUID.randomUUID();
        callSetup(userId);

        HttpResponse<String> response = callVerify(userId, "12");

        assertEquals(400, response.statusCode());
    }

    // ================= Helper methods =================

    private HttpResponse<String> callSetup(String userId) throws Exception {
        String body = String.format("{\"userId\":\"%s\",\"label\":\"%s@EnterpriseIAM\"}", userId, userId);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/setup"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> callVerify(String userId, String code) throws Exception {
        String body = String.format("{\"userId\":\"%s\",\"code\":\"%s\"}", userId, code);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/verify"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String extractOtpauthUri(HttpResponse<String> setupResponse) throws Exception {
        JsonNode json = objectMapper.readTree(setupResponse.body());
        return json.get("otpauthUri").asText();
    }

    private String generateCodeFromUri(String otpauthUri) throws Exception {
        Map<String, String> params = parseQueryParams(otpauthUri);
        String secret = params.get("secret");
        int period = Integer.parseInt(params.getOrDefault("period", "30"));

        long counter = Math.floorDiv(timeProvider.getTime(), period);
        return codeGenerator.generate(secret, counter);
    }

    private Map<String, String> parseQueryParams(String otpauthUri) {
        Map<String, String> result = new HashMap<>();
        String query = otpauthUri.substring(otpauthUri.indexOf('?') + 1);
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            result.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
        }
        return result;
    }
}