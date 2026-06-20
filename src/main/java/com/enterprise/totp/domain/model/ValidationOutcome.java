package com.enterprise.totp.domain.model;


public sealed interface ValidationOutcome
        permits ValidationOutcome.Success,
                ValidationOutcome.InvalidCode,
                ValidationOutcome.ReplayDetected,
                ValidationOutcome.UserNotFound,
                ValidationOutcome.MfaDisabled,
                ValidationOutcome.CryptoError {

    record Success() implements ValidationOutcome {}
    record InvalidCode() implements ValidationOutcome {}
    record ReplayDetected() implements ValidationOutcome {}
    record UserNotFound() implements ValidationOutcome {}
    record MfaDisabled() implements ValidationOutcome {}
    record CryptoError(String reason) implements ValidationOutcome {}
}

