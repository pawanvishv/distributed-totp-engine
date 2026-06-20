package com.enterprise.totp.application;

import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;
import com.enterprise.totp.api.exception.InvalidTotpCodeException;
import com.enterprise.totp.api.exception.MfaNotEnabledException;
import com.enterprise.totp.api.exception.ReplayAttackException;
import com.enterprise.totp.api.exception.UserNotFoundException;
import com.enterprise.totp.application.port.MfaVerificationUseCase;
import com.enterprise.totp.domain.engine.TotpEngine;
import com.enterprise.totp.domain.replay.ReplayCache;
import com.enterprise.totp.infrastructure.base32.Base32Codec;
import com.enterprise.totp.infrastructure.crypto.SecretEncryptionService;
import com.enterprise.totp.infrastructure.persistence.entity.UserMfaProfile;
import com.enterprise.totp.infrastructure.persistence.repository.UserMfaProfileRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Map;


@Service
@Transactional(readOnly = true)
public class MfaVerificationServiceImpl implements MfaVerificationUseCase {

    private final UserMfaProfileRepository repository;
    private final SecretEncryptionService encryptionService;
    private final TotpEngine totpEngine;
    private final ReplayCache replayCache;

    public MfaVerificationServiceImpl(UserMfaProfileRepository repository,
                                       SecretEncryptionService encryptionService,
                                       TotpEngine totpEngine,
                                       ReplayCache replayCache) {
        this.repository = repository;
        this.encryptionService = encryptionService;
        this.totpEngine = totpEngine;
        this.replayCache = replayCache;
    }

    @Override
    public VerifyResponse verify(VerifyRequest request) {
        String userId = request.userId();
        String submittedCode = request.code();

        UserMfaProfile profile = repository.findByUserId(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));

        if (!profile.isEnabled()) {
            throw new MfaNotEnabledException(userId);
        }

        byte[] rawSecret = null;
        try {
            byte[] encryptedBytes = encryptionService.decrypt(profile.getEncryptedSecret());
            String base32Secret = new String(encryptedBytes, StandardCharsets.UTF_8);
            rawSecret = Base32Codec.decode(base32Secret);

            Map<Long, String> validCodes = totpEngine.generateValidCodes(rawSecret, profile.getAlgorithm());
            boolean matched = false;
            long matchedStep = -1L;
            byte[] submittedBytes = submittedCode.getBytes(StandardCharsets.UTF_8);

            for (Map.Entry<Long, String> entry : validCodes.entrySet()) {
                if (MessageDigest.isEqual(
                        submittedBytes,
                        entry.getValue().getBytes(StandardCharsets.UTF_8))) {
                    if (!matched) {
                        matched = true;
                        matchedStep = entry.getKey();
                    }
                }
            }

            if (!matched) {
                throw new InvalidTotpCodeException();
            }
            boolean firstUse = replayCache.markUsed(userId, submittedCode, matchedStep);
            if (!firstUse) {
                throw new ReplayAttackException();
            }

            return VerifyResponse.success();

        } finally {
            if (rawSecret != null) {
                Arrays.fill(rawSecret, (byte) 0);
            }
        }
    }
}

