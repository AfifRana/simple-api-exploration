package com.example.auth.dto.request;

import jakarta.validation.constraints.NotBlank;

public record SocialLoginRequest(
        @NotBlank String provider,
        @NotBlank String idToken,
        String deviceInfo
) {
}
