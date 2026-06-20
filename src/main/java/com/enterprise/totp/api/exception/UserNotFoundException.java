package com.enterprise.totp.api.exception;

public class UserNotFoundException extends TotpException {
    public UserNotFoundException(String userId) {
        super("Authentication failed for user: " + userId);
    }
}

