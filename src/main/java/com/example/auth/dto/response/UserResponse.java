package com.example.auth.dto.response;

public record UserResponse(
        Long id,
        String email,
        boolean emailVerified,
        String roles
) {
}
