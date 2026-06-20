package com.enterprise.totp.api.exception;

public class MfaNotEnabledException extends TotpException {
    public MfaNotEnabledException(String userId) {
        super("MFA is not enabled for user: " + userId);
    }
}

