package com.enterprise.totp.domain.algorithm;

import java.util.EnumMap;
import java.util.Map;


public class TotpStrategyFactory {

    private final Map<HmacAlgorithm, TotpStrategy> strategies;

    public TotpStrategyFactory() {
        strategies = new EnumMap<>(HmacAlgorithm.class);
        for (HmacAlgorithm alg : HmacAlgorithm.values()) {
            strategies.put(alg, new HmacTotpStrategy(alg));
        }
    }

    
    public TotpStrategy getStrategy(HmacAlgorithm algorithm) {
        TotpStrategy strategy = strategies.get(algorithm);
        if (strategy == null) {
            throw new IllegalArgumentException("No strategy registered for algorithm: " + algorithm);
        }
        return strategy;
    }
}

