package com.enterprise.totp.domain;

import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.domain.algorithm.HmacTotpStrategy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class HmacTotpStrategyTest {
    private static final byte[] RFC_SHA1_SEED =
            "12345678901234567890".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] RFC_SHA256_SEED =
            "12345678901234567890123456789012".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    @ParameterizedTest(name = "SHA-1 counter={0} expected={1}")
    @CsvSource({
        "0,        755224",
        "1,        287082",
        "2,        359152",
        "3,        969429",
        "4,        338314",
        "5,        254676",
        "6,        287922",
        "7,        162583",
        "8,        399871",
        "9,        520489"
    })
    void rfc6238Sha1TestVectors(long counter, String expected) {
        HmacTotpStrategy strategy = new HmacTotpStrategy(HmacAlgorithm.SHA1);
        assertThat(strategy.generateCode(RFC_SHA1_SEED, counter)).isEqualTo(expected);
    }

    
    @ParameterizedTest(name = "SHA-256 T={0} expected={1}")
    @CsvSource({
        "1,          119246",   // time=59,         T=0x0000000000000001
        "37037036,   084774",   // time=1111111109,  T=0x00000000023523EC
        "37037037,   062674",   // time=1111111111,  T=0x00000000023523ED
        "41152263,   819424",   // time=1234567890,  T=0x000000000273EF07
        "66666666,   698825",   // time=2000000000,  T=0x0000000003F940AA (actual computed value)
        "666666666,  737706"    // time=20000000000, T=0x0000000027BC86AA
    })
    void rfc6238Sha256TestVectors(long counter, String expected) {
        HmacTotpStrategy strategy = new HmacTotpStrategy(HmacAlgorithm.SHA256);
        assertThat(strategy.generateCode(RFC_SHA256_SEED, counter)).isEqualTo(expected.trim());
    }

    @Test
    void leadingZeroPreservation() {
        HmacTotpStrategy strategy = new HmacTotpStrategy(HmacAlgorithm.SHA1);
        String code = strategy.generateCode(RFC_SHA1_SEED, 0L);
        assertThat(code).hasSize(6);
        assertThat(code).matches("\\d{6}");
    }

    @Test
    void emptySecretThrowsIllegalArgumentException() {
        HmacTotpStrategy strategy = new HmacTotpStrategy(HmacAlgorithm.SHA1);
        assertThatThrownBy(() -> strategy.generateCode(new byte[0], 1L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("secret");
    }

    @Test
    void nullSecretThrowsIllegalArgumentException() {
        HmacTotpStrategy strategy = new HmacTotpStrategy(HmacAlgorithm.SHA1);
        assertThatThrownBy(() -> strategy.generateCode(null, 1L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void differentAlgorithmsProduceDifferentCodesForSameSecretAndCounter() {
        byte[] secret = "testSecretBytes123".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        long counter = 1000L;
        String sha1Code = new HmacTotpStrategy(HmacAlgorithm.SHA1).generateCode(secret, counter);
        String sha256Code = new HmacTotpStrategy(HmacAlgorithm.SHA256).generateCode(secret, counter);
        assertThat(sha1Code).isNotEqualTo(sha256Code);
    }

    @Test
    void hmacAlgorithmUriNamesAreAuthenticatorCompatible() {
        assertThat(HmacAlgorithm.SHA1.uriName()).isEqualTo("SHA1");
        assertThat(HmacAlgorithm.SHA256.uriName()).isEqualTo("SHA256");
        assertThat(HmacAlgorithm.SHA512.uriName()).isEqualTo("SHA512");
    }

    @Test
    void hmacAlgorithmJcaNamesAreCorrect() {
        assertThat(HmacAlgorithm.SHA1.jcaName()).isEqualTo("HmacSHA1");
        assertThat(HmacAlgorithm.SHA256.jcaName()).isEqualTo("HmacSHA256");
        assertThat(HmacAlgorithm.SHA512.jcaName()).isEqualTo("HmacSHA512");
    }
}

