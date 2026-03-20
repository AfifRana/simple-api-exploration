package com.example.auth.controller;

import com.example.auth.dto.response.JwksResponse;
import com.example.auth.security.RsaKeyProvider;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

@RestController
public class JwksController {

    private final RsaKeyProvider rsaKeyProvider;

    public JwksController(RsaKeyProvider rsaKeyProvider) {
        this.rsaKeyProvider = rsaKeyProvider;
    }

    @GetMapping("/.well-known/jwks.json")
    public JwksResponse getJwks() {
        RSAPublicKey publicKey = rsaKeyProvider.getPublicKey();
        return new JwksResponse(List.of(new JwksResponse.JwkKey(
                "RSA",
                rsaKeyProvider.getKid(),
                "sig",
                "RS256",
                encodeBigInt(publicKey.getModulus()),
                encodeBigInt(publicKey.getPublicExponent())
        )));
    }

    private String encodeBigInt(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            bytes = trimmed;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
