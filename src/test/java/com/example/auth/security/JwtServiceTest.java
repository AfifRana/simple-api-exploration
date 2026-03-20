package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import com.example.auth.domain.User;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceTest {

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setIssuer("https://auth.test");
        properties.getJwt().setKeyId("test-v1");
        properties.getJwt().setAccessTokenExpiryMinutes(15);
        properties.getJwt().getKeystore().setMode("generate");
        RsaKeyProvider keyProvider = new RsaKeyProvider(properties, new DefaultResourceLoader());
        keyProvider.init();
        jwtService = new JwtService(properties, keyProvider);
    }

    @Test
    void shouldGenerateAndValidateToken() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash("hash")
                .emailVerified(true)
                .roles("USER")
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();

        String token = jwtService.generateAccessToken(user);
        Claims claims = jwtService.parseAndValidate(token);

        assertThat(claims.getSubject()).isEqualTo("1");
        assertThat(claims.get("email", String.class)).isEqualTo("user@example.com");
    }
}
