package com.enterprise.totp.application.port;

import com.enterprise.totp.api.dto.SetupRequest;
import com.enterprise.totp.api.dto.SetupResponse;


public interface MfaSetupUseCase {

    
    SetupResponse setup(SetupRequest request);
}

