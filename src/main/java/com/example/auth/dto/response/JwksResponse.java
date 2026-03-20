package com.example.auth.dto.response;

import java.util.List;

public record JwksResponse(List<JwkKey> keys) {
    public record JwkKey(
            String kty,
            String kid,
            String use,
            String alg,
            String n,
            String e
    ) {
    }
}
