package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import com.example.auth.exception.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

@Service
public class ExternalTokenValidator {

    private final AuthProperties authProperties;
    private final ExternalJwksService externalJwksService;

    public ExternalTokenValidator(AuthProperties authProperties, ExternalJwksService externalJwksService) {
        this.authProperties = authProperties;
        this.externalJwksService = externalJwksService;
    }

    public ExternalPrincipal validate(String providerName, String idToken) {
        AuthProperties.Provider provider = authProperties.getJwks().getProviders().get(providerName);
        if (provider == null) {
            throw new AuthException("UNSUPPORTED_PROVIDER", HttpStatus.BAD_REQUEST, "Unsupported external provider");
        }
        String kid = extractKid(idToken);
        PublicKey publicKey = externalJwksService.findKey(provider.getJwksUri(), kid);
        Claims claims = Jwts.parser()
                .verifyWith((java.security.PublicKey) publicKey)
                .requireIssuer(provider.getIssuer())
                .build()
                .parseSignedClaims(idToken)
                .getPayload();

        Object audience = claims.get("aud");
        boolean audienceValid = false;
        if (audience instanceof String value) {
            audienceValid = provider.getAudience().equals(value);
        } else if (audience instanceof Iterable<?> values) {
            for (Object value : values) {
                if (provider.getAudience().equals(String.valueOf(value))) {
                    audienceValid = true;
                    break;
                }
            }
        }
        if (!audienceValid) {
            throw new AuthException("INVALID_EXTERNAL_AUDIENCE", HttpStatus.UNAUTHORIZED, "Invalid external token audience");
        }

        String email = claims.get("email", String.class);
        if (email == null || email.isBlank()) {
            throw new AuthException("EXTERNAL_EMAIL_MISSING", HttpStatus.UNAUTHORIZED, "External token missing email claim");
        }
        return new ExternalPrincipal(email, claims.getSubject(), providerName, claims);
    }

    private String extractKid(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Invalid JWT");
            }
            byte[] decoded = Base64.getUrlDecoder().decode(parts[0]);
            @SuppressWarnings("unchecked")
            Map<String, Object> header = new com.fasterxml.jackson.databind.ObjectMapper().readValue(decoded, Map.class);
            Object kid = header.get("kid");
            if (kid == null) {
                throw new IllegalArgumentException("Missing kid");
            }
            return kid.toString();
        } catch (Exception ex) {
            throw new AuthException("INVALID_EXTERNAL_TOKEN", HttpStatus.UNAUTHORIZED, "Invalid external token header");
        }
    }

    public record ExternalPrincipal(String email, String subject, String provider, Claims claims) {
    }
}
