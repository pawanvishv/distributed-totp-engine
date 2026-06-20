package com.enterprise.totp.application;

import com.enterprise.totp.api.dto.SetupRequest;
import com.enterprise.totp.api.dto.SetupResponse;
import com.enterprise.totp.api.exception.MfaAlreadyEnabledException;
import com.enterprise.totp.application.port.MfaSetupUseCase;
import com.enterprise.totp.config.TotpProperties;
import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.infrastructure.base32.Base32Codec;
import com.enterprise.totp.infrastructure.crypto.SecretEncryptionService;
import com.enterprise.totp.infrastructure.persistence.entity.UserMfaProfile;
import com.enterprise.totp.infrastructure.persistence.repository.UserMfaProfileRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;


@Service
@Transactional
public class MfaSetupServiceImpl implements MfaSetupUseCase {

    private final UserMfaProfileRepository repository;
    private final SecretEncryptionService encryptionService;
    private final TotpProperties properties;
    private final MeterRegistry meterRegistry;

    public MfaSetupServiceImpl(UserMfaProfileRepository repository,
                                SecretEncryptionService encryptionService,
                                TotpProperties properties,
                                MeterRegistry meterRegistry) {
        this.repository = repository;
        this.encryptionService = encryptionService;
        this.properties = properties;
        this.meterRegistry = meterRegistry;
    }

    @Override
    public SetupResponse setup(SetupRequest request) {
        String userId = request.userId();
        String label = request.label();
        Optional<UserMfaProfile> existing = repository.findByUserId(userId);
        if (existing.isPresent() && existing.get().isEnabled()) {
            meterRegistry.counter("mfa.setup.conflict").increment();
            throw new MfaAlreadyEnabledException(userId);
        }
        byte[] rawSecret = new byte[20];
        new SecureRandom().nextBytes(rawSecret);

        String base32Secret = Base32Codec.encode(rawSecret);
        String encryptedSecret = encryptionService.encrypt(base32Secret.getBytes(StandardCharsets.UTF_8));

        HmacAlgorithm algorithm = HmacAlgorithm.fromName(properties.getAlgorithm());

        UserMfaProfile profile = existing
                .map(p -> {
                    p.setEncryptedSecret(encryptedSecret);
                    p.setAlgorithm(algorithm);
                    p.setEnabled(true);
                    return p;
                })
                .orElseGet(() -> new UserMfaProfile(userId, encryptedSecret, algorithm));

        repository.save(profile);

        String otpauthUri = buildOtpauthUri(base32Secret, label, algorithm);
        meterRegistry.counter("mfa.setup.success").increment();

        return new SetupResponse(otpauthUri);
    }

    private String buildOtpauthUri(String base32Secret, String label, HmacAlgorithm algorithm) {
        String labelEncoded = URLEncoder.encode(label, StandardCharsets.UTF_8);
        String issuerEncoded = URLEncoder.encode(properties.getIssuerName(), StandardCharsets.UTF_8);

        return "otpauth://totp/" + labelEncoded
                + "?secret=" + base32Secret
                + "&issuer=" + issuerEncoded
                + "&algorithm=" + algorithm.uriName()
                + "&digits=6"
                + "&period=" + properties.getTimeStepSeconds();
    }
}

