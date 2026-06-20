package com.enterprise.totp.api.exception;

public class ReplayAttackException extends TotpException {
    public ReplayAttackException() {
        super("The submitted TOTP code has already been used");
    }
}

