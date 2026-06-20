package com.enterprise.totp.config;

import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.domain.engine.TotpEngine;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;


@Component
public class JitWarmupRunner {

    private static final Logger log = LoggerFactory.getLogger(JitWarmupRunner.class);
    private static final byte[] WARMUP_SECRET = new byte[20];
    static {
        for (int i = 0; i < WARMUP_SECRET.length; i++) {
            WARMUP_SECRET[i] = (byte) (i + 1);
        }
    }

    private final TotpProperties properties;
    private final TotpEngine totpEngine;
    private final MeterRegistry meterRegistry;

    public JitWarmupRunner(TotpProperties properties,
                            TotpEngine totpEngine,
                            MeterRegistry meterRegistry) {
        this.properties = properties;
        this.totpEngine = totpEngine;
        this.meterRegistry = meterRegistry;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void warmUpJit() {
        if (!properties.getWarmup().isEnabled()) {
            log.info("jit.warmup: disabled (totp.warmup.enabled=false)");
            return;
        }

        int iterations = properties.getWarmup().getIterations();
        log.info("jit.warmup: Starting {} synthetic TOTP generation cycles to prime JIT", iterations);

        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            totpEngine.generateValidCodes(WARMUP_SECRET, HmacAlgorithm.SHA1);
        }
        long durationMs = (System.nanoTime() - start) / 1_000_000;

        meterRegistry.counter("mfa.jit_warmup.iterations").increment(iterations);
        log.info("jit.warmup: Complete. {} iterations in {}ms. JIT hot path primed.", iterations, durationMs);
    }
}

