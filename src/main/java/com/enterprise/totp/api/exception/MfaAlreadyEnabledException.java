package com.enterprise.totp.api.exception;

public class MfaAlreadyEnabledException extends TotpException {
    public MfaAlreadyEnabledException(String userId) {
        super("MFA is already enabled for user: " + userId);
    }
}

