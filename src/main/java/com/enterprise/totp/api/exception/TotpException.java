package com.enterprise.totp.api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;


@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class TotpException extends RuntimeException {

    public TotpException(String message) {
        super(message);
    }

    public TotpException(String message, Throwable cause) {
        super(message, cause);
    }
}

