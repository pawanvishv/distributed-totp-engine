package com.enterprise.totp.api.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;
import java.util.stream.Collectors;


@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final String AUTH_FAILURE_TYPE =
            "https://api.enterprise.com/errors/authentication-failure";
    private static final String AUTH_FAILURE_TITLE = "Authentication Failed";
    private static final String AUTH_FAILURE_DETAIL =
            "The submitted credentials are invalid.";

    @ExceptionHandler({
        UserNotFoundException.class,
        InvalidTotpCodeException.class,
        ReplayAttackException.class,
        MfaNotEnabledException.class
    })
    public ProblemDetail handleAuthFailure(TotpException ex) {
        log.debug("Authentication failure [{}]: {}", ex.getClass().getSimpleName(), ex.getMessage());
        ProblemDetail problem = buildProblemDetail(HttpStatus.UNAUTHORIZED, AUTH_FAILURE_TYPE,
                AUTH_FAILURE_TITLE, AUTH_FAILURE_DETAIL);
        problem.setProperty("debugException", ex.getClass().getSimpleName());
        problem.setProperty("debugMessage", ex.getMessage());
        return problem;
    }

    @ExceptionHandler(MfaAlreadyEnabledException.class)
    public ProblemDetail handleAlreadyEnabled(MfaAlreadyEnabledException ex) {
        return buildProblemDetail(HttpStatus.CONFLICT,
                "https://api.enterprise.com/errors/mfa-already-enabled",
                "MFA Already Enabled",
                "MFA is already active for this account. Disable it first before re-enrolling.");
    }

    @ExceptionHandler(OptimisticLockingFailureException.class)
    public ProblemDetail handleOptimisticLock(OptimisticLockingFailureException ex) {
        return buildProblemDetail(HttpStatus.CONFLICT,
                "https://api.enterprise.com/errors/concurrent-modification",
                "Concurrent Modification",
                "A concurrent modification occurred. Please retry.");
    }

    @ExceptionHandler(ServiceUnavailableException.class)
    public ProblemDetail handleServiceUnavailable(ServiceUnavailableException ex) {
        log.warn("Service unavailable: {}", ex.getMessage());
        return buildProblemDetail(HttpStatus.SERVICE_UNAVAILABLE,
                "https://api.enterprise.com/errors/service-unavailable",
                "Service Unavailable",
                "The MFA service is temporarily unavailable. Please retry shortly.");
    }

    @ExceptionHandler(EncryptionException.class)
    public ProblemDetail handleEncryption(EncryptionException ex) {
        log.error("Encryption error (potential data tampering detected): {}", ex.getMessage());
        return buildProblemDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                "https://api.enterprise.com/errors/internal-error",
                "Internal Server Error",
                "An internal error occurred. Please contact support.");
    }

    @ExceptionHandler(TotpException.class)
    public ProblemDetail handleGenericTotp(TotpException ex) {
        log.error("Unhandled TOTP exception: {}", ex.getMessage(), ex);
        return buildProblemDetail(HttpStatus.INTERNAL_SERVER_ERROR,
                "https://api.enterprise.com/errors/internal-error",
                "Internal Server Error",
                "An internal error occurred.");
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ProblemDetail handleValidation(MethodArgumentNotValidException ex) {
        String fieldErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));

        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.BAD_REQUEST, "Validation failed: " + fieldErrors);
        problem.setType(URI.create("https://api.enterprise.com/errors/validation-failure"));
        problem.setTitle("Validation Failed");
        problem.setProperty("timestamp", Instant.now().toString());
        return problem;
    }

    private ProblemDetail buildProblemDetail(HttpStatus status, String type,
                                              String title, String detail) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setType(URI.create(type));
        problem.setTitle(title);
        problem.setProperty("timestamp", Instant.now().toString());
        return problem;
    }
}

