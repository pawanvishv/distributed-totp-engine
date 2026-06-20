package com.enterprise.totp.api;

import com.enterprise.totp.api.exception.*;
import com.enterprise.totp.application.port.MfaSetupUseCase;
import com.enterprise.totp.application.port.MfaVerificationUseCase;
import com.enterprise.totp.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest
@Import({GlobalExceptionHandler.class, SecurityConfig.class})
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private MfaSetupUseCase setupUseCase;

    @MockBean
    private MfaVerificationUseCase verificationUseCase;

    @Test
    void mfaAlreadyEnabledReturns409() throws Exception {
        when(setupUseCase.setup(any())).thenThrow(new MfaAlreadyEnabledException("alice"));

        mockMvc.perform(post("/api/v1/mfa/setup")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"label\":\"My App\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409))
                .andExpect(jsonPath("$.title").value("MFA Already Enabled"));
    }

    @Test
    void userNotFoundReturns401WithGenericMessage() throws Exception {
        when(verificationUseCase.verify(any())).thenThrow(new UserNotFoundException("bob"));

        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"bob\",\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("The submitted credentials are invalid."));
    }

    @Test
    void invalidTotpCodeReturns401WithSameBodyAsUserNotFound() throws Exception {
        when(verificationUseCase.verify(any())).thenThrow(new InvalidTotpCodeException());

        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"000000\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("The submitted credentials are invalid."));
    }

    @Test
    void replayAttackReturns401WithSameBodyAsInvalidCode() throws Exception {
        when(verificationUseCase.verify(any())).thenThrow(new ReplayAttackException());

        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("The submitted credentials are invalid."));
    }

    @Test
    void responseBodyDoesNotContainInternalDetails() throws Exception {
        when(verificationUseCase.verify(any())).thenThrow(new ReplayAttackException());

        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"123456\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("replay"))))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("not found"))))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("disabled"))));
    }

    @Test
    void encryptionExceptionReturns500() throws Exception {
        when(verificationUseCase.verify(any())).thenThrow(new EncryptionException("tampered"));

        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"123456\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500));
    }

    @Test
    void blankUserIdReturns400() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"\",\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void colonInUserIdReturns400() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice:bob\",\"code\":\"123456\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void fiveDigitCodeReturns400() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"12345\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void nonNumericCodeReturns400() throws Exception {
        mockMvc.perform(post("/api/v1/mfa/verify")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"userId\":\"alice\",\"code\":\"12345a\"}"))
                .andExpect(status().isBadRequest());
    }
}

