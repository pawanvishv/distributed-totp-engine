package com.enterprise.totp.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;


public record SetupRequest(
        @NotBlank(message = "userId must not be blank")
        @Size(max = 255, message = "userId must not exceed 255 characters")
        @Pattern(regexp = "[^:]+", message = "userId must not contain colon (:) characters")
        String userId,

        @NotBlank(message = "label must not be blank")
        @Size(max = 255, message = "label must not exceed 255 characters")
        String label
) {}

