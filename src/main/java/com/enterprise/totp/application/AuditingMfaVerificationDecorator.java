package com.enterprise.totp.application;

import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;
import com.enterprise.totp.application.port.MfaVerificationUseCase;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;


@Primary
@Component
public class AuditingMfaVerificationDecorator implements MfaVerificationUseCase {

    private static final Logger log = LoggerFactory.getLogger(AuditingMfaVerificationDecorator.class);

    private final MfaVerificationUseCase delegate;
    private final MeterRegistry meterRegistry;

    public AuditingMfaVerificationDecorator(
            @Qualifier("mfaVerificationServiceImpl") MfaVerificationUseCase delegate,
            MeterRegistry meterRegistry) {
        this.delegate = delegate;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public VerifyResponse verify(VerifyRequest request) {
        String hashedUserId = hashUserId(request.userId());
        String requestId = MDC.get("requestId");
        log.info("event=mfa.verify.attempt userId={} requestId={}", hashedUserId, requestId);

        Timer.Sample sample = Timer.start(meterRegistry);
        String outcome = "SUCCESS";

        try {
            VerifyResponse result = delegate.verify(request);

            long durationMs = recordTimer(sample, outcome);
            if (durationMs > 20) {
                log.warn("event=mfa.verify.slow_request userId={} durationMs={} threshold_ms=20",
                        hashedUserId, durationMs);
            }
            log.info("event=mfa.verify.success userId={} durationMs={} requestId={}",
                    hashedUserId, durationMs, requestId);
            return result;

        } catch (Exception e) {
            boolean knownBusinessFailure = isKnownBusinessFailure(e);
            outcome = knownBusinessFailure ? resolveOutcome(e) : "SERVICE_ERROR";
            long durationMs = recordTimer(sample, outcome);
            if (knownBusinessFailure) {
                log.warn("event=mfa.verify.failure userId={} outcome={} durationMs={} requestId={}",
                        hashedUserId, outcome, durationMs, requestId);
                meterRegistry.counter("mfa.verify.failure", "outcome", toMetricOutcome(outcome)).increment();
            } else {
                log.error("event=mfa.verify.error userId={} outcome=SERVICE_ERROR durationMs={} requestId={}",
                        hashedUserId, durationMs, requestId, e);
                meterRegistry.counter("mfa.verify.error").increment();
            }
            throw e;
        }
    }

    private long recordTimer(Timer.Sample sample, String outcome) {
        sample.stop(Timer.builder("mfa.verify.duration")
                .tag("outcome", outcome)
                .publishPercentiles(0.5, 0.95, 0.99, 0.999)
                .publishPercentileHistogram()
                .serviceLevelObjectives(
                        Duration.ofMillis(1),
                        Duration.ofMillis(5),
                        Duration.ofMillis(20))
                .register(meterRegistry));
        return System.nanoTime() / 1_000_000; // approximate; actual measured by timer
    }

    private String resolveOutcome(Exception exception) {
        String simpleName = exception.getClass().getSimpleName();
        return switch (simpleName) {
            case "InvalidTotpCodeException" -> "INVALID_CODE";
            case "ReplayAttackException" -> "REPLAY_DETECTED";
            case "UserNotFoundException" -> "USER_NOT_FOUND";
            case "MfaNotEnabledException" -> "MFA_DISABLED";
            default -> "SERVICE_ERROR";
        };
    }

    private boolean isKnownBusinessFailure(Exception exception) {
        String simpleName = exception.getClass().getSimpleName();
        return "InvalidTotpCodeException".equals(simpleName)
                || "ReplayAttackException".equals(simpleName)
                || "UserNotFoundException".equals(simpleName)
                || "MfaNotEnabledException".equals(simpleName);
    }

    private String toMetricOutcome(String outcome) {
        return switch (outcome) {
            case "INVALID_CODE" -> "invalid_code";
            case "REPLAY_DETECTED" -> "replay_detected";
            case "USER_NOT_FOUND" -> "user_not_found";
            case "MFA_DISABLED" -> "mfa_disabled";
            default -> "service_error";
        };
    }

    
    private String hashUserId(String userId) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(userId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes).substring(0, 16); // first 8 bytes for brevity
        } catch (Exception e) {
            return "HASH_ERROR";
        }
    }
}

