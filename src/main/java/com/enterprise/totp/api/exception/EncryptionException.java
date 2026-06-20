package com.enterprise.totp.api.exception;

public class EncryptionException extends TotpException {
    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}

