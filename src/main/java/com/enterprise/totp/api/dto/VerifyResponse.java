package com.enterprise.totp.api.dto;


public record VerifyResponse(boolean verified, String message) {

    public static VerifyResponse success() {
        return new VerifyResponse(true, "Authentication successful");
    }
}

