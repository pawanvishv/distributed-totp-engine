package com.enterprise.totp.api.exception;

public class ServiceUnavailableException extends TotpException {
    public ServiceUnavailableException(String message) {
        super(message);
    }
}

