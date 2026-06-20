package com.enterprise.totp.infrastructure.crypto;


public interface SecretEncryptionService {

    
    String encrypt(byte[] plaintext);

    
    byte[] decrypt(String encryptedBase64);
}

