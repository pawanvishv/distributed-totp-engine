package com.enterprise.totp.domain.model;


public record TotpWindowResult(boolean matched, long timeStep) {

    public static TotpWindowResult noMatch() {
        return new TotpWindowResult(false, -1L);
    }

    public static TotpWindowResult match(long timeStep) {
        return new TotpWindowResult(true, timeStep);
    }
}

