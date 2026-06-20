package com.enterprise.totp.api.controller;

import com.enterprise.totp.api.dto.SetupRequest;
import com.enterprise.totp.api.dto.SetupResponse;
import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;
import com.enterprise.totp.application.port.MfaSetupUseCase;
import com.enterprise.totp.application.port.MfaVerificationUseCase;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/v1/mfa")
public class MfaController {

    private final MfaSetupUseCase setupUseCase;
    private final MfaVerificationUseCase verificationUseCase;

    public MfaController(MfaSetupUseCase setupUseCase,
                          MfaVerificationUseCase verificationUseCase) {
        this.setupUseCase = setupUseCase;
        this.verificationUseCase = verificationUseCase;
    }

    
    @PostMapping("/setup")
    public ResponseEntity<SetupResponse> setup(@Valid @RequestBody SetupRequest request) {
        SetupResponse response = setupUseCase.setup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    
    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
        VerifyResponse response = verificationUseCase.verify(request);
        return ResponseEntity.ok(response);
    }
}

