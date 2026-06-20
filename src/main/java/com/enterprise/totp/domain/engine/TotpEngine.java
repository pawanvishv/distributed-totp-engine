package com.enterprise.totp.domain.engine;

import com.enterprise.totp.config.TotpProperties;
import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.domain.algorithm.TotpStrategy;
import com.enterprise.totp.domain.algorithm.TotpStrategyFactory;
import com.enterprise.totp.domain.clock.ClockSource;

import java.util.LinkedHashMap;
import java.util.Map;


public class TotpEngine {

    private final ClockSource clockSource;
    private final TotpProperties properties;
    private final TotpStrategyFactory strategyFactory;

    public TotpEngine(ClockSource clockSource,
                      TotpProperties properties,
                      TotpStrategyFactory strategyFactory) {
        this.clockSource = clockSource;
        this.properties = properties;
        this.strategyFactory = strategyFactory;
    }

    
    public Map<Long, String> generateValidCodes(byte[] secret, HmacAlgorithm algorithm) {
        long now = clockSource.currentTimeMillis();
        if (now < 0) {
            throw new IllegalStateException(
                    "ClockSource returned negative time: " + now + ". Check system clock.");
        }

        long stepMillis = (long) properties.getTimeStepSeconds() * 1000L;
        long currentStep = now / stepMillis;
        int skewWindow = properties.getSkewWindow();

        TotpStrategy strategy = strategyFactory.getStrategy(algorithm);

        Map<Long, String> codes = new LinkedHashMap<>((skewWindow * 2 + 1) * 2);
        for (long step = currentStep - skewWindow; step <= currentStep + skewWindow; step++) {
            codes.put(step, strategy.generateCode(secret, step));
        }
        return codes;
    }
}

