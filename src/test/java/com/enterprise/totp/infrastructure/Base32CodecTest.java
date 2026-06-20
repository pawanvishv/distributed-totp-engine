package com.enterprise.totp.infrastructure;

import com.enterprise.totp.infrastructure.base32.Base32Codec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Base32CodecTest {

    
    @ParameterizedTest(name = "\"{0}\" â†’ \"{1}\"")
    @CsvSource({
        "f,      MY======",
        "fo,     MZXQ====",
        "foo,    MZXW6===",
        "foob,   MZXW6YQ=",
        "fooba,  MZXW6YTB",
        "foobar, MZXW6YTBOI======"
    })
    void rfc4648AppendixCTestVectors(String input, String expectedBase32) {
        byte[] inputBytes = input.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        assertThat(Base32Codec.encode(inputBytes)).isEqualTo(expectedBase32.trim());
    }

    @Test
    void encodeEmptyReturnsEmpty() {
        assertThat(Base32Codec.encode(new byte[0])).isEmpty();
    }

    @Test
    void decodeEmptyReturnsEmpty() {
        assertThat(Base32Codec.decode("")).isEmpty();
    }

    @Test
    void decodeWithPadding() {
        byte[] original = "fo".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] decoded = Base32Codec.decode("MZXQ====");
        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void decodeWithoutPadding() {
        byte[] original = "fo".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] decoded = Base32Codec.decode("MZXQ");
        assertThat(decoded).isEqualTo(original);
    }

    @Test
    void invalidCharacterThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> Base32Codec.decode("MZXQ1234")) // '1' invalid in Base32
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid Base32 character");
    }

    @Test
    void roundTripForAllPaddingLengths() {
        for (int len = 1; len <= 7; len++) {
            byte[] input = new byte[len];
            new SecureRandom().nextBytes(input);
            byte[] decoded = Base32Codec.decode(Base32Codec.encode(input));
            assertThat(decoded)
                    .as("Round-trip failed for length %d", len)
                    .isEqualTo(input);
        }
    }

    @Test
    void propertyBasedRoundTrip10kArrays() {
        SecureRandom rng = new SecureRandom();
        for (int i = 0; i < 10_000; i++) {
            int length = 1 + rng.nextInt(64);
            byte[] input = new byte[length];
            rng.nextBytes(input);
            byte[] decoded = Base32Codec.decode(Base32Codec.encode(input));
            assertThat(decoded)
                    .as("Round-trip failed at iteration %d, length=%d", i, length)
                    .isEqualTo(input);
        }
    }
}

