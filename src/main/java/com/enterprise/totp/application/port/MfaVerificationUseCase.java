package com.enterprise.totp.application.port;

import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;


public interface MfaVerificationUseCase {

    
    VerifyResponse verify(VerifyRequest request);
}

