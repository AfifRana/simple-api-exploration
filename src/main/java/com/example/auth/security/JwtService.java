package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import com.example.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    private final AuthProperties authProperties;
    private final RsaKeyProvider rsaKeyProvider;

    public JwtService(AuthProperties authProperties, RsaKeyProvider rsaKeyProvider) {
        this.authProperties = authProperties;
        this.rsaKeyProvider = rsaKeyProvider;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(authProperties.getJwt().getAccessTokenExpiryMinutes() * 60);
        return Jwts.builder()
                .header().keyId(rsaKeyProvider.getKid()).and()
                .issuer(authProperties.getJwt().getIssuer())
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("roles", user.getRoles())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(rsaKeyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    public Claims parseAndValidate(String token) throws SignatureException {
        return Jwts.parser()
                .verifyWith(rsaKeyProvider.getPublicKey())
                .requireIssuer(authProperties.getJwt().getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public long getAccessTokenExpirySeconds() {
        return authProperties.getJwt().getAccessTokenExpiryMinutes() * 60;
    }

    public List<String> getRoles(Claims claims) {
        Object raw = claims.get("roles");
        if (raw == null) {
            return List.of("USER");
        }
        return List.of(raw.toString().split(","));
    }
}
