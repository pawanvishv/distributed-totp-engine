package com.enterprise.totp.config;

import com.enterprise.totp.domain.clock.ClockSource;
import com.enterprise.totp.domain.algorithm.TotpStrategyFactory;
import com.enterprise.totp.domain.engine.TotpEngine;
import com.enterprise.totp.domain.replay.InMemoryReplayCache;
import com.enterprise.totp.domain.replay.ReplayCache;
import com.enterprise.totp.infrastructure.crypto.AesGcmEncryptionService;
import com.enterprise.totp.infrastructure.crypto.SecretEncryptionService;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.Base64;
import java.util.concurrent.TimeUnit;


@Configuration
public class CacheConfig {

    private static final Logger log = LoggerFactory.getLogger(CacheConfig.class);

    @Bean
    public ClockSource clockSource() {
        return System::currentTimeMillis;
    }

    @Bean
    public TotpStrategyFactory totpStrategyFactory() {
        return new TotpStrategyFactory();
    }

    @Bean
    public TotpEngine totpEngine(ClockSource clockSource,
                                  TotpProperties properties,
                                  TotpStrategyFactory strategyFactory) {
        return new TotpEngine(clockSource, properties, strategyFactory);
    }

    @Bean
    public ReplayCache replayCache() {
        log.warn("replay.cache.cold_start: In-memory replay cache initialized empty. " +
                "Codes from the previous TOTP window may be replayed immediately after restart. " +
                "Upgrade to Redis-backed cache to eliminate this risk in multi-replica deployments.");
        return new InMemoryReplayCache();
    }

    @Bean
    public SecretEncryptionService secretEncryptionService(TotpProperties properties,
                                                            MeterRegistry meterRegistry,
                                                            Environment environment) {
        String keyEnvVar = properties.getEncryption().getKeyEnvVar();
        String keyBase64 = System.getenv(keyEnvVar);
        if (keyBase64 == null || keyBase64.isBlank()) {
            keyBase64 = environment.getProperty(keyEnvVar);
        }
        if (keyBase64 == null || keyBase64.isBlank()) {
            keyBase64 = System.getProperty(keyEnvVar);
        }
        if (keyBase64 == null || keyBase64.isBlank()) {
            throw new IllegalStateException(
                    "AES encryption key variable/property '" + keyEnvVar + "' is not set. " +
                    "The service cannot start without a valid 32-byte Base64-encoded AES key.");
        }
        try {
            byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
            return new AesGcmEncryptionService(keyBytes, meterRegistry);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(
                    "Environment variable '" + keyEnvVar + "' is not valid Base64", e);
        }
    }

    
    @Bean
    public CacheManager cacheManager(MeterRegistry meterRegistry) {
        com.github.benmanes.caffeine.cache.Cache<Object, Object> caffeineCache =
                Caffeine.newBuilder()
                        .maximumSize(100_000)
                        .expireAfterWrite(5, TimeUnit.MINUTES)
                        .recordStats()
                        .build();

        CaffeineCacheMetrics.monitor(meterRegistry, caffeineCache, "mfa.l2_cache");

        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(100_000)
                .expireAfterWrite(5, TimeUnit.MINUTES)
                .recordStats());
        return cacheManager;
    }
}

