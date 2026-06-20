package com.enterprise.totp.application;

import com.enterprise.totp.api.dto.VerifyRequest;
import com.enterprise.totp.api.dto.VerifyResponse;
import com.enterprise.totp.api.exception.InvalidTotpCodeException;
import com.enterprise.totp.api.exception.ReplayAttackException;
import com.enterprise.totp.api.exception.UserNotFoundException;
import com.enterprise.totp.application.port.MfaVerificationUseCase;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditingMfaVerificationDecoratorTest {

    @Mock
    private MfaVerificationUseCase delegate;

    private AuditingMfaVerificationDecorator decorator;

    @BeforeEach
    void setUp() {
        decorator = new AuditingMfaVerificationDecorator(delegate, new SimpleMeterRegistry());
    }

    @Test
    void delegatesCallToWrappedService() {
        VerifyRequest request = new VerifyRequest("alice", "123456");
        VerifyResponse expected = VerifyResponse.success();
        when(delegate.verify(request)).thenReturn(expected);

        VerifyResponse result = decorator.verify(request);

        assertThat(result).isEqualTo(expected);
        verify(delegate).verify(request);
    }

    @Test
    void onSuccessReturnsResult() {
        VerifyRequest request = new VerifyRequest("alice", "123456");
        when(delegate.verify(request)).thenReturn(VerifyResponse.success());

        VerifyResponse result = decorator.verify(request);
        assertThat(result.verified()).isTrue();
    }

    @Test
    void onInvalidCodeExceptionRethrows() {
        VerifyRequest request = new VerifyRequest("alice", "000000");
        when(delegate.verify(request)).thenThrow(new InvalidTotpCodeException());

        assertThatThrownBy(() -> decorator.verify(request))
                .isInstanceOf(InvalidTotpCodeException.class);
    }

    @Test
    void onReplayAttackExceptionRethrows() {
        VerifyRequest request = new VerifyRequest("alice", "123456");
        when(delegate.verify(request)).thenThrow(new ReplayAttackException());

        assertThatThrownBy(() -> decorator.verify(request))
                .isInstanceOf(ReplayAttackException.class);
    }

    @Test
    void onUserNotFoundExceptionRethrows() {
        VerifyRequest request = new VerifyRequest("unknown", "123456");
        when(delegate.verify(request)).thenThrow(new UserNotFoundException("unknown"));

        assertThatThrownBy(() -> decorator.verify(request))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void onUnexpectedRuntimeExceptionRethrows() {
        VerifyRequest request = new VerifyRequest("alice", "123456");
        when(delegate.verify(request)).thenThrow(new RuntimeException("DB down"));

        assertThatThrownBy(() -> decorator.verify(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DB down");
    }
}

