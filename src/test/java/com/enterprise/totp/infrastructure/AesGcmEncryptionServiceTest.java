package com.enterprise.totp.infrastructure;

import com.enterprise.totp.api.exception.EncryptionException;
import com.enterprise.totp.infrastructure.crypto.AesGcmEncryptionService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmEncryptionServiceTest {

    private AesGcmEncryptionService service;
    private byte[] validKey;

    @BeforeEach
    void setUp() {
        validKey = new byte[32];
        new SecureRandom().nextBytes(validKey);
        service = new AesGcmEncryptionService(validKey, new SimpleMeterRegistry());
    }

    @Test
    void encryptDecryptRoundTrip() {
        byte[] plaintext = "test-totp-secret".getBytes();
        String encrypted = service.encrypt(plaintext);
        byte[] decrypted = service.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void twoEncryptionsOfSamePlaintextProduceDifferentCiphertexts() {
        byte[] plaintext = "same-plaintext".getBytes();
        String enc1 = service.encrypt(plaintext);
        String enc2 = service.encrypt(plaintext);
        assertThat(enc1).isNotEqualTo(enc2); // different IVs
    }

    @Test
    void tamperedCiphertextThrowsEncryptionException() {
        byte[] plaintext = "sensitive-data".getBytes();
        String encrypted = service.encrypt(plaintext);
        byte[] envelope = Base64.getDecoder().decode(encrypted);
        envelope[20] ^= 0xFF; // tamper
        String tampered = Base64.getEncoder().encodeToString(envelope);

        assertThatThrownBy(() -> service.decrypt(tampered))
                .isInstanceOf(EncryptionException.class);
    }

    @Test
    void keyLengthNot32BytesThrowsIllegalArgumentException() {
        byte[] shortKey = new byte[16];
        assertThatThrownBy(() -> new AesGcmEncryptionService(shortKey, new SimpleMeterRegistry()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void nullKeyThrowsIllegalArgumentException() {
        assertThatThrownBy(() -> new AesGcmEncryptionService(null, new SimpleMeterRegistry()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void concurrentEncryptDecryptFromMultipleThreadsProducesNoErrors() throws Exception {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<Boolean>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                byte[] data = ("secret-" + index).getBytes();
                String encrypted = service.encrypt(data);
                byte[] decrypted = service.decrypt(encrypted);
                return java.util.Arrays.equals(data, decrypted);
            }));
        }

        for (Future<Boolean> f : futures) {
            assertThat(f.get()).isTrue();
        }
        executor.shutdown();
    }

    @Test
    void decryptionWorksAfterNewInstanceWithSameKey() {
        byte[] plaintext = "persistent-secret".getBytes();
        String encrypted = service.encrypt(plaintext);
        AesGcmEncryptionService newInstance = new AesGcmEncryptionService(validKey, new SimpleMeterRegistry());
        byte[] decrypted = newInstance.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(plaintext);
    }
}

