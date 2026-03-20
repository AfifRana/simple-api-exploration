package com.example.auth.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    public void sendVerificationToken(String email, String token) {
        log.info("Verification token for {} -> {}", email, token);
    }

    public void sendPasswordResetToken(String email, String token) {
        log.info("Password reset token for {} -> {}", email, token);
    }
}
