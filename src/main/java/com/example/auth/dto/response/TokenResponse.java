package com.example.auth.dto.response;

public record TokenResponse(
        String accessToken,
        long expiresIn,
        String refreshToken
) {
}
