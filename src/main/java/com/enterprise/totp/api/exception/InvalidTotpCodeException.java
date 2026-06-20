package com.enterprise.totp.api.exception;

public class InvalidTotpCodeException extends TotpException {
    public InvalidTotpCodeException() {
        super("The submitted TOTP code is invalid or expired");
    }
}

