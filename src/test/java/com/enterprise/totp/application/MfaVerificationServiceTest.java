package com.enterprise.totp.application;

import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;
import com.enterprise.totp.api.exception.*;
import com.enterprise.totp.config.TotpProperties;
import com.enterprise.totp.domain.algorithm.HmacAlgorithm;
import com.enterprise.totp.domain.algorithm.TotpStrategyFactory;
import com.enterprise.totp.domain.clock.ClockSource;
import com.enterprise.totp.domain.engine.TotpEngine;
import com.enterprise.totp.domain.replay.ReplayCache;
import com.enterprise.totp.infrastructure.base32.Base32Codec;
import com.enterprise.totp.infrastructure.crypto.SecretEncryptionService;
import com.enterprise.totp.infrastructure.persistence.entity.UserMfaProfile;
import com.enterprise.totp.infrastructure.persistence.repository.UserMfaProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MfaVerificationServiceTest {

    @Mock
    private UserMfaProfileRepository repository;

    @Mock
    private SecretEncryptionService encryptionService;

    @Mock
    private ReplayCache replayCache;

    private MfaVerificationServiceImpl service;
    private static final long FIXED_TIME_MS = 1_000_000L;
    private static final byte[] RAW_SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final String BASE32_SECRET = Base32Codec.encode(RAW_SECRET);

    @BeforeEach
    void setUp() {
        TotpProperties properties = new TotpProperties();
        properties.setTimeStepSeconds(30);
        properties.setSkewWindow(1);
        properties.setAlgorithm("SHA1");

        ClockSource fixedClock = () -> FIXED_TIME_MS;
        TotpStrategyFactory strategyFactory = new TotpStrategyFactory();
        TotpEngine engine = new TotpEngine(fixedClock, properties, strategyFactory);

        service = new MfaVerificationServiceImpl(repository, encryptionService, engine, replayCache);
    }

    @Test
    void unknownUserThrowsUserNotFoundException() {
        when(repository.findByUserId("unknown")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.verify(new VerifyRequest("unknown", "123456")))
                .isInstanceOf(UserNotFoundException.class);
        verify(replayCache, never()).markUsed(any(), any(), anyLong());
    }

    @Test
    void disabledProfileThrowsMfaNotEnabledException() {
        UserMfaProfile profile = new UserMfaProfile("alice", "encrypted", HmacAlgorithm.SHA1);
        profile.setEnabled(false);
        when(repository.findByUserId("alice")).thenReturn(Optional.of(profile));

        assertThatThrownBy(() -> service.verify(new VerifyRequest("alice", "123456")))
                .isInstanceOf(MfaNotEnabledException.class);
        verify(replayCache, never()).markUsed(any(), any(), anyLong());
    }

    @Test
    void encryptionExceptionPropagates() {
        UserMfaProfile profile = new UserMfaProfile("alice", "encrypted", HmacAlgorithm.SHA1);
        when(repository.findByUserId("alice")).thenReturn(Optional.of(profile));
        when(encryptionService.decrypt(anyString())).thenThrow(new EncryptionException("tampered"));

        assertThatThrownBy(() -> service.verify(new VerifyRequest("alice", "123456")))
                .isInstanceOf(EncryptionException.class);
        verify(replayCache, never()).markUsed(any(), any(), anyLong());
    }

    @Test
    void invalidCodeThrowsInvalidTotpCodeException() {
        UserMfaProfile profile = new UserMfaProfile("alice", "encrypted", HmacAlgorithm.SHA1);
        when(repository.findByUserId("alice")).thenReturn(Optional.of(profile));
        when(encryptionService.decrypt(anyString()))
                .thenReturn(BASE32_SECRET.getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> service.verify(new VerifyRequest("alice", "000000")))
                .isInstanceOf(InvalidTotpCodeException.class);
        verify(replayCache, never()).markUsed(any(), any(), anyLong());
    }

    @Test
    void replayReturnsFalseThrowsReplayAttackException() {
        UserMfaProfile profile = new UserMfaProfile("alice", "encrypted", HmacAlgorithm.SHA1);
        when(repository.findByUserId("alice")).thenReturn(Optional.of(profile));
        when(encryptionService.decrypt(anyString()))
                .thenReturn(BASE32_SECRET.getBytes(StandardCharsets.UTF_8));
        when(replayCache.markUsed(anyString(), anyString(), anyLong())).thenReturn(false);
        TotpProperties properties = new TotpProperties();
        properties.setTimeStepSeconds(30);
        long step = FIXED_TIME_MS / (30L * 1000L);
        String validCode = new com.enterprise.totp.domain.algorithm.HmacTotpStrategy(HmacAlgorithm.SHA1)
                .generateCode(RAW_SECRET, step);

        assertThatThrownBy(() -> service.verify(new VerifyRequest("alice", validCode)))
                .isInstanceOf(ReplayAttackException.class);
    }

    @Test
    void validCodeSucceeds() {
        UserMfaProfile profile = new UserMfaProfile("alice", "encrypted", HmacAlgorithm.SHA1);
        when(repository.findByUserId("alice")).thenReturn(Optional.of(profile));
        when(encryptionService.decrypt(anyString()))
                .thenReturn(BASE32_SECRET.getBytes(StandardCharsets.UTF_8));
        when(replayCache.markUsed(anyString(), anyString(), anyLong())).thenReturn(true);

        long step = FIXED_TIME_MS / (30L * 1000L);
        String validCode = new com.enterprise.totp.domain.algorithm.HmacTotpStrategy(HmacAlgorithm.SHA1)
                .generateCode(RAW_SECRET, step);

        VerifyResponse result = service.verify(new VerifyRequest("alice", validCode));
        assertThat(result.verified()).isTrue();
        verify(replayCache, times(1)).markUsed("alice", validCode, step);
    }
}

