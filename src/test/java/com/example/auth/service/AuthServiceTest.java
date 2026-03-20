package com.example.auth.service;

import com.example.auth.config.AuthProperties;
import com.example.auth.domain.User;
import com.example.auth.dto.request.LoginRequest;
import com.example.auth.dto.request.SignupRequest;
import com.example.auth.dto.response.TokenResponse;
import com.example.auth.dto.response.UserResponse;
import com.example.auth.exception.AuthException;
import com.example.auth.repository.FlowTokenRepository;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.ExternalTokenValidator;
import com.example.auth.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private FlowTokenRepository flowTokenRepository;
    @Mock
    private JwtService jwtService;
    @Mock
    private NotificationService notificationService;
    @Mock
    private ExternalTokenValidator externalTokenValidator;

    private AuthService authService;

    @BeforeEach
    void setUp() {
        PasswordEncoder encoder = new BCryptPasswordEncoder();
        AuthProperties properties = new AuthProperties();
        properties.getJwt().setRefreshTokenExpiryDays(30);
        properties.getJwt().setAccessTokenExpiryMinutes(15);
        authService = new AuthService(
                userRepository,
                refreshTokenRepository,
                flowTokenRepository,
                encoder,
                jwtService,
                notificationService,
                externalTokenValidator,
                properties
        );
    }

    @Test
    void signupShouldCreateUser() {
        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            user.setId(10L);
            user.setCreatedAt(Instant.now());
            user.setUpdatedAt(Instant.now());
            return user;
        });

        UserResponse response = authService.signup(new SignupRequest("test@example.com", "Password123!"));

        assertThat(response.id()).isEqualTo(10L);
        assertThat(response.email()).isEqualTo("test@example.com");
    }

    @Test
    void loginShouldReturnTokenResponse() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash(new BCryptPasswordEncoder().encode("Password123!"))
                .roles("USER")
                .emailVerified(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(any(User.class))).thenReturn("access-token");
        when(jwtService.getAccessTokenExpirySeconds()).thenReturn(900L);

        TokenResponse response = authService.login(new LoginRequest("user@example.com", "Password123!", "device"));

        assertThat(response.accessToken()).isEqualTo("access-token");
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void loginShouldFailForWrongPassword() {
        User user = User.builder()
                .id(1L)
                .email("user@example.com")
                .passwordHash(new BCryptPasswordEncoder().encode("Password123!"))
                .roles("USER")
                .emailVerified(true)
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .build();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest("user@example.com", "wrong-pass", "device")))
                .isInstanceOf(AuthException.class);
    }
}
