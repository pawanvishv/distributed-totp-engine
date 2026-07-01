package com.enterprise.totp.testutil;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Standalone dev/test utility to simulate an authenticator app.
 * NOT part of the production service — used only for local testing
 * of the setup -> verify flow.
 */
public class TotpTestClientUtil {

    private static final CodeGenerator CODE_GENERATOR = new DefaultCodeGenerator();
    private static final TimeProvider TIME_PROVIDER = new SystemTimeProvider();

    public static void main(String[] args) throws Exception {
        // Paste the otpauthUri received from /api/v1/mfa/setup
        String otpauthUri = "otpauth://totp/user126%40EnterpriseIAM?secret=HT4223BZPWOYYDZ3T2ZSFUYTCYUFWCD4&issuer=EnterpriseIAM&algorithm=SHA1&digits=6&period=60";
        String userId = "user126";
        boolean callVerifyApi = false; // set false to just print the code
        String verifyEndpoint = "http://localhost:8080/api/v1/mfa/verify";

        Map<String, String> params = parseQueryParams(otpauthUri);
        String secret = params.get("secret");
        int period = Integer.parseInt(params.getOrDefault("period", "30"));

        long counter = Math.floorDiv(TIME_PROVIDER.getTime(), period);
        String code = CODE_GENERATOR.generate(secret, counter);

        System.out.println("Generated TOTP code: " + code);

//        if (callVerifyApi) {
//            callVerify(verifyEndpoint, userId, code);
//        }
    }

    private static Map<String, String> parseQueryParams(String otpauthUri) {
        Map<String, String> result = new HashMap<>();
        String query = otpauthUri.substring(otpauthUri.indexOf('?') + 1);
        for (String pair : query.split("&")) {
            String[] kv = pair.split("=", 2);
            String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
            result.put(key, value);
        }
        return result;
    }

    private static void callVerify(String endpoint, String userId, String code) throws Exception {
        String body = String.format("{\"userId\":\"%s\",\"code\":\"%s\"}", userId, code);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println("Verify API status: " + response.statusCode());
        System.out.println("Verify API response: " + response.body());
    }
}