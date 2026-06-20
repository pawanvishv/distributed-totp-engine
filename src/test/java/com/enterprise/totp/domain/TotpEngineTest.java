package com.enterprise.totp.domain;

import com.enterprise.totp.config.TotpProperties;
import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.domain.algorithm.TotpStrategyFactory;
import com.enterprise.totp.domain.engine.TotpEngine;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpEngineTest {

    private TotpProperties properties;
    private TotpStrategyFactory strategyFactory;
    private static final byte[] SECRET = "testSecret12345678".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    @BeforeEach
    void setUp() {
        properties = new TotpProperties();
        properties.setTimeStepSeconds(30);
        strategyFactory = new TotpStrategyFactory();
    }

    @Test
    void windowSizeIsCorrectForSkew0() {
        properties.setSkewWindow(0);
        long fixedTime = 1_000_000L; // step = 33
        TotpEngine engine = new TotpEngine(() -> fixedTime, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        assertThat(codes).hasSize(1);
    }

    @Test
    void windowSizeIsCorrectForSkew1() {
        properties.setSkewWindow(1);
        TotpEngine engine = new TotpEngine(() -> 1_000_000L, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        assertThat(codes).hasSize(3); // step-1, step, step+1
    }

    @Test
    void windowSizeIsCorrectForSkew5() {
        properties.setSkewWindow(5);
        TotpEngine engine = new TotpEngine(() -> 1_000_000L, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        assertThat(codes).hasSize(11); // 2*5+1
        assertThat(codes.keySet()).doesNotHaveDuplicates();
    }

    @Test
    void centerEntryKeyEqualsCurrentStep() {
        long fixedTime = 900_000L; // step = 900_000 / 30_000 = 30
        properties.setSkewWindow(1);
        TotpEngine engine = new TotpEngine(() -> fixedTime, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        long currentStep = fixedTime / (30L * 1000L);
        assertThat(codes).containsKey(currentStep);
    }

    @Test
    void stepOutsideWindowIsAbsent() {
        long fixedTime = 900_000L; // step = 30
        properties.setSkewWindow(1);
        TotpEngine engine = new TotpEngine(() -> fixedTime, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        long currentStep = fixedTime / (30L * 1000L);
        assertThat(codes).doesNotContainKey(currentStep - 2);
        assertThat(codes).doesNotContainKey(currentStep + 2);
    }

    @Test
    void allCodesAreSixDigitStrings() {
        properties.setSkewWindow(2);
        TotpEngine engine = new TotpEngine(() -> 1_000_000L, properties, strategyFactory);

        Map<Long, String> codes = engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1);
        codes.values().forEach(code -> assertThat(code).matches("\\d{6}"));
    }

    @Test
    void negativeClockValueThrowsIllegalStateException() {
        TotpEngine engine = new TotpEngine(() -> -1L, properties, strategyFactory);
        assertThatThrownBy(() -> engine.generateValidCodes(SECRET, HmacAlgorithm.SHA1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("negative time");
    }
}

