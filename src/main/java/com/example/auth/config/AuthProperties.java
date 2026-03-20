package com.example.auth.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {

    private Jwt jwt = new Jwt();
    private Jwks jwks = new Jwks();
    private RateLimit rateLimit = new RateLimit();

    @Getter
    @Setter
    public static class Jwt {
        @NotBlank
        private String issuer;
        @NotBlank
        private String keyId;
        @Min(1)
        private long accessTokenExpiryMinutes = 15;
        @Min(1)
        private long refreshTokenExpiryDays = 30;
        private Keystore keystore = new Keystore();
    }

    @Getter
    @Setter
    public static class Keystore {
        @NotBlank
        private String mode = "generate";
        @NotBlank
        private String path = "classpath:auth-keystore.p12";
        @NotBlank
        private String password = "changeit";
        @NotBlank
        private String alias = "auth-jwt";
    }

    @Getter
    @Setter
    public static class Jwks {
        @Min(1)
        private long cacheTtlMinutes = 60;
        private Map<String, Provider> providers = new HashMap<>();
    }

    @Getter
    @Setter
    public static class Provider {
        @NotBlank
        private String jwksUri;
        @NotBlank
        private String issuer;
        @NotBlank
        private String audience;
    }

    @Getter
    @Setter
    public static class RateLimit {
        @Min(1)
        private long loginPerMinute = 5;
        @Min(1)
        private long passwordResetPerMinute = 5;
        @Min(1)
        private long socialLoginPerMinute = 10;
    }
}
