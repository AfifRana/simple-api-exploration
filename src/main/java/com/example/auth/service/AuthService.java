package com.example.auth.service;

import com.example.auth.config.AuthProperties;
import com.example.auth.domain.*;
import com.example.auth.dto.request.*;
import com.example.auth.dto.response.TokenResponse;
import com.example.auth.dto.response.UserResponse;
import com.example.auth.exception.AuthException;
import com.example.auth.repository.FlowTokenRepository;
import com.example.auth.repository.RefreshTokenRepository;
import com.example.auth.repository.UserRepository;
import com.example.auth.security.ExternalTokenValidator;
import com.example.auth.security.JwtService;
import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final FlowTokenRepository flowTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final NotificationService notificationService;
    private final ExternalTokenValidator externalTokenValidator;
    private final AuthProperties authProperties;

    public AuthService(UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       FlowTokenRepository flowTokenRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       NotificationService notificationService,
                       ExternalTokenValidator externalTokenValidator,
                       AuthProperties authProperties) {
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.flowTokenRepository = flowTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.notificationService = notificationService;
        this.externalTokenValidator = externalTokenValidator;
        this.authProperties = authProperties;
    }

    @Transactional
    public UserResponse signup(SignupRequest request) {
        String email = request.email().toLowerCase();
        if (userRepository.existsByEmail(email)) {
            throw new AuthException("EMAIL_EXISTS", HttpStatus.CONFLICT, "Email already exists");
        }
        Instant now = Instant.now();
        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(request.password()))
                .emailVerified(false)
                .roles("USER")
                .createdAt(now)
                .updatedAt(now)
                .build();
        userRepository.save(user);

        String verifyToken = newOpaqueToken();
        flowTokenRepository.save(FlowToken.builder()
                .user(user)
                .tokenHash(hashToken(verifyToken))
                .type(FlowTokenType.VERIFY_EMAIL)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(24 * 3600))
                .build());
        notificationService.sendVerificationToken(user.getEmail(), verifyToken);

        return toUserResponse(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email().toLowerCase())
                .orElseThrow(() -> new AuthException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED, "Invalid credentials"));
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new AuthException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }
        return issueTokens(user, request.deviceInfo());
    }

    @Transactional
    public TokenResponse socialLogin(SocialLoginRequest request) {
        ExternalTokenValidator.ExternalPrincipal principal = externalTokenValidator.validate(request.provider(), request.idToken());
        User user = userRepository.findByEmail(principal.email().toLowerCase()).orElseGet(() -> userRepository.save(
                User.builder()
                        .email(principal.email().toLowerCase())
                        .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                        .emailVerified(true)
                        .roles("USER")
                        .createdAt(Instant.now())
                        .updatedAt(Instant.now())
                        .build()
        ));
        return issueTokens(user, request.deviceInfo());
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        String hash = hashToken(request.refreshToken());
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new AuthException("INVALID_REFRESH_TOKEN", HttpStatus.UNAUTHORIZED, "Invalid refresh token"));
        if (stored.getRevokedAt() != null) {
            revokeAllSessions(stored.getUser());
            throw new AuthException("REVOKED_REFRESH_TOKEN", HttpStatus.FORBIDDEN, "Refresh token revoked");
        }
        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("EXPIRED_REFRESH_TOKEN", HttpStatus.UNAUTHORIZED, "Refresh token expired");
        }
        stored.setRevokedAt(Instant.now());
        refreshTokenRepository.save(stored);
        return issueTokens(stored.getUser(), stored.getDeviceInfo());
    }

    @Transactional
    public void logout(LogoutRequest request) {
        refreshTokenRepository.findByTokenHash(hashToken(request.refreshToken()))
                .ifPresent(token -> {
                    if (token.getRevokedAt() == null) {
                        token.setRevokedAt(Instant.now());
                        refreshTokenRepository.save(token);
                    }
                });
    }

    @Transactional
    public void requestPasswordReset(PasswordResetRequest request) {
        userRepository.findByEmail(request.email().toLowerCase()).ifPresent(user -> {
            String resetToken = newOpaqueToken();
            flowTokenRepository.save(FlowToken.builder()
                    .user(user)
                    .tokenHash(hashToken(resetToken))
                    .type(FlowTokenType.PASSWORD_RESET)
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .build());
            notificationService.sendPasswordResetToken(user.getEmail(), resetToken);
        });
    }

    @Transactional
    public void confirmPasswordReset(PasswordResetConfirmRequest request) {
        FlowToken token = flowTokenRepository.findByTokenHashAndType(hashToken(request.token()), FlowTokenType.PASSWORD_RESET)
                .orElseThrow(() -> new AuthException("INVALID_RESET_TOKEN", HttpStatus.BAD_REQUEST, "Invalid reset token"));
        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("INVALID_RESET_TOKEN", HttpStatus.BAD_REQUEST, "Invalid reset token");
        }
        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        token.setUsedAt(Instant.now());
        flowTokenRepository.save(token);
        revokeAllSessions(user);
    }

    @Transactional
    public void verifyEmail(VerifyEmailRequest request) {
        FlowToken token = flowTokenRepository.findByTokenHashAndType(hashToken(request.token()), FlowTokenType.VERIFY_EMAIL)
                .orElseThrow(() -> new AuthException("INVALID_VERIFY_TOKEN", HttpStatus.BAD_REQUEST, "Invalid verification token"));
        if (token.getUsedAt() != null || token.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("INVALID_VERIFY_TOKEN", HttpStatus.BAD_REQUEST, "Invalid verification token");
        }
        User user = token.getUser();
        user.setEmailVerified(true);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        token.setUsedAt(Instant.now());
        flowTokenRepository.save(token);
    }

    public UserResponse me(String email) {
        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new AuthException("USER_NOT_FOUND", HttpStatus.NOT_FOUND, "User not found"));
        return toUserResponse(user);
    }

    private TokenResponse issueTokens(User user, String deviceInfo) {
        String accessToken = jwtService.generateAccessToken(user);
        String refreshTokenValue = newOpaqueToken();
        refreshTokenRepository.save(RefreshToken.builder()
                .user(user)
                .tokenHash(hashToken(refreshTokenValue))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(authProperties.getJwt().getRefreshTokenExpiryDays() * 86400))
                .deviceInfo(deviceInfo)
                .build());
        return new TokenResponse(accessToken, jwtService.getAccessTokenExpirySeconds(), refreshTokenValue);
    }

    private void revokeAllSessions(User user) {
        var tokens = refreshTokenRepository.findAllByUser(user);
        tokens.forEach(token -> {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(Instant.now());
            }
        });
        refreshTokenRepository.saveAll(tokens);
    }

    private UserResponse toUserResponse(User user) {
        return new UserResponse(user.getId(), user.getEmail(), user.isEmailVerified(), user.getRoles());
    }

    private String newOpaqueToken() {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString((UUID.randomUUID() + ":" + UUID.randomUUID()).getBytes(StandardCharsets.UTF_8));
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash token", ex);
        }
    }
}
