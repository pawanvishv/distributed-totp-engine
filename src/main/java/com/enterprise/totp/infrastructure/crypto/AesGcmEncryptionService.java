package com.enterprise.totp.infrastructure.crypto;

import com.enterprise.totp.api.exception.EncryptionException;
import io.micrometer.core.instrument.MeterRegistry;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;


public class AesGcmEncryptionService implements SecretEncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecretKeySpec secretKeySpec;
    private final MeterRegistry meterRegistry;

    public AesGcmEncryptionService(byte[] keyBytes, MeterRegistry meterRegistry) {
        if (keyBytes == null || keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "AES key must be exactly 32 bytes (256 bits), got: "
                    + (keyBytes == null ? "null" : keyBytes.length));
        }
        this.secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        this.meterRegistry = meterRegistry;
    }

    @Override
    public String encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] envelope = new byte[IV_LENGTH_BYTES + ciphertext.length];
            System.arraycopy(iv, 0, envelope, 0, IV_LENGTH_BYTES);
            System.arraycopy(ciphertext, 0, envelope, IV_LENGTH_BYTES, ciphertext.length);

            return Base64.getEncoder().encodeToString(envelope);
        } catch (Exception e) {
            throw new EncryptionException("Encryption failed", e);
        }
    }

    @Override
    public byte[] decrypt(String encryptedBase64) {
        byte[] envelope = Base64.getDecoder().decode(encryptedBase64);

        if (envelope.length <= IV_LENGTH_BYTES) {
            throw new EncryptionException("Ciphertext envelope is too short");
        }

        byte[] iv = Arrays.copyOfRange(envelope, 0, IV_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(envelope, IV_LENGTH_BYTES, envelope.length);

        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            meterRegistry.counter("mfa.crypto.tamper_detected").increment();
            throw new EncryptionException("GCM tag verification failed â€” ciphertext may be tampered", e);
        } catch (Exception e) {
            throw new EncryptionException("Decryption failed", e);
        }
    }
}

