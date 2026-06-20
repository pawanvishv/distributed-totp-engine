package com.enterprise.totp.domain.algorithm;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class HmacTotpStrategy implements TotpStrategy {

    private final HmacAlgorithm algorithm;


    public HmacTotpStrategy(HmacAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    
    @Override
    public String generateCode(byte[] secret, long counter) {
        if (secret == null || secret.length == 0) {
            throw new IllegalArgumentException("TOTP secret must not be null or empty");
        }

        byte[] hmac = computeHmac(secret, counter);
        int offset = hmac[hmac.length - 1] & 0x0F;
        int binCode = ((hmac[offset]     & 0x7F) << 24)
                    | ((hmac[offset + 1] & 0xFF) << 16)
                    | ((hmac[offset + 2] & 0xFF) << 8)
                    |  (hmac[offset + 3] & 0xFF);

        int otp = binCode % 1_000_000;
        return String.format("%06d", otp);
    }

    private byte[] computeHmac(byte[] secret, long counter) {
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();

        try {
            Mac mac = Mac.getInstance(algorithm.jcaName());
            SecretKeySpec keySpec = new SecretKeySpec(secret, algorithm.jcaName());
            mac.init(keySpec);
            return mac.doFinal(counterBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HMAC algorithm not available: " + algorithm.jcaName(), e);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException("Invalid TOTP secret key for algorithm " + algorithm.jcaName(), e);
        }
    }
}

