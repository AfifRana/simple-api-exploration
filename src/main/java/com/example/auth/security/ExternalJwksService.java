package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import com.example.auth.exception.AuthException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ExternalJwksService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final AuthProperties authProperties;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public ExternalJwksService(RestTemplate restTemplate, ObjectMapper objectMapper, AuthProperties authProperties) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.authProperties = authProperties;
    }

    public PublicKey findKey(String jwksUri, String kid) {
        CacheEntry entry = cache.get(jwksUri);
        if (entry == null || entry.isExpired(authProperties.getJwks().getCacheTtlMinutes()) || !entry.keys.containsKey(kid)) {
            entry = fetchAndCache(jwksUri);
        }
        PublicKey key = entry.keys.get(kid);
        if (key == null) {
            entry = fetchAndCache(jwksUri);
            key = entry.keys.get(kid);
        }
        if (key == null) {
            throw new AuthException("EXTERNAL_KEY_NOT_FOUND", HttpStatus.UNAUTHORIZED, "No matching key for token kid");
        }
        return key;
    }

    private CacheEntry fetchAndCache(String jwksUri) {
        try {
            String body = restTemplate.getForObject(jwksUri, String.class);
            JsonNode root = objectMapper.readTree(body);
            JsonNode keysNode = root.get("keys");
            Map<String, PublicKey> keys = new HashMap<>();
            Iterator<JsonNode> iterator = keysNode.elements();
            while (iterator.hasNext()) {
                JsonNode node = iterator.next();
                if (!"RSA".equals(node.path("kty").asText())) {
                    continue;
                }
                String kid = node.path("kid").asText();
                String n = node.path("n").asText();
                String e = node.path("e").asText();
                keys.put(kid, buildRsaKey(n, e));
            }
            CacheEntry entry = new CacheEntry(keys, Instant.now());
            cache.put(jwksUri, entry);
            return entry;
        } catch (Exception ex) {
            throw new AuthException("JWKS_FETCH_FAILED", HttpStatus.UNAUTHORIZED, "Unable to fetch external JWKS");
        }
    }

    private PublicKey buildRsaKey(String modulusBase64Url, String exponentBase64Url) throws Exception {
        BigInteger modulus = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(modulusBase64Url));
        BigInteger exponent = new BigInteger(1, java.util.Base64.getUrlDecoder().decode(exponentBase64Url));
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private record CacheEntry(Map<String, PublicKey> keys, Instant createdAt) {
        private boolean isExpired(long ttlMinutes) {
            return Duration.between(createdAt, Instant.now()).toMinutes() >= ttlMinutes;
        }
    }
}
