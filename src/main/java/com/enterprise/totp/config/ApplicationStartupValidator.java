package com.enterprise.totp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Base64;


@Component
public class ApplicationStartupValidator implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(ApplicationStartupValidator.class);

    private final TotpProperties properties;
    private final Environment environment;

    public ApplicationStartupValidator(TotpProperties properties, Environment environment) {
        this.properties = properties;
        this.environment = environment;
    }

    @Override
    public void run(ApplicationArguments args) {
        String keyEnvVar = properties.getEncryption().getKeyEnvVar();
        String keyValue = System.getenv(keyEnvVar);
        if (keyValue == null || keyValue.isBlank()) {
            keyValue = environment.getProperty(keyEnvVar);
        }
        if (keyValue == null || keyValue.isBlank()) {
            keyValue = System.getProperty(keyEnvVar);
        }

        if (keyValue == null || keyValue.isBlank()) {
            log.error("startup.validation FAILED: Environment variable '{}' is not set or empty. " +
                    "A Base64-encoded 32-byte AES-256 key is required.", keyEnvVar);
            throw new IllegalStateException(
                    "Required environment variable '" + keyEnvVar + "' is not set");
        }

        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyValue);
            if (keyBytes.length != 32) {
                log.error("startup.validation FAILED: AES key length={} bytes, expected=32. " +
                        "Env var '{}' must contain a Base64-encoded 32-byte (256-bit) key.",
                        keyBytes.length, keyEnvVar);
                throw new IllegalStateException(
                        "AES key must be exactly 32 bytes (256 bits), got: " + keyBytes.length);
            }
            log.info("startup.validation OK: AES key validated from env var '{}', length=32 bytes",
                    keyEnvVar);
        } catch (IllegalArgumentException e) {
            log.error("startup.validation FAILED: Cannot Base64-decode env var '{}': {}",
                    keyEnvVar, e.getMessage());
            throw new IllegalStateException(
                    "Environment variable '" + keyEnvVar + "' is not valid Base64", e);
        }
    }
}

