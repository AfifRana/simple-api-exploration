package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
public class RsaKeyProvider {

    private final AuthProperties authProperties;
    private final ResourceLoader resourceLoader;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public RsaKeyProvider(AuthProperties authProperties, ResourceLoader resourceLoader) {
        this.authProperties = authProperties;
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    void init() {
        String mode = authProperties.getJwt().getKeystore().getMode();
        if ("file".equalsIgnoreCase(mode)) {
            loadFromKeystore();
            return;
        }
        generateEphemeral();
    }

    private void generateEphemeral() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            this.publicKey = (RSAPublicKey) pair.getPublic();
            this.privateKey = (RSAPrivateKey) pair.getPrivate();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Failed generating RSA key pair", ex);
        }
    }

    private void loadFromKeystore() {
        try {
            AuthProperties.Keystore keystore = authProperties.getJwt().getKeystore();
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            try (InputStream inputStream = resourceLoader.getResource(keystore.getPath()).getInputStream()) {
                keyStore.load(inputStream, keystore.getPassword().toCharArray());
            }
            Key key = keyStore.getKey(keystore.getAlias(), keystore.getPassword().toCharArray());
            if (!(key instanceof RSAPrivateKey rsaPrivateKey)) {
                throw new IllegalStateException("Keystore private key is not RSA");
            }
            Certificate certificate = keyStore.getCertificate(keystore.getAlias());
            this.privateKey = rsaPrivateKey;
            this.publicKey = (RSAPublicKey) certificate.getPublicKey();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed loading RSA key from keystore", ex);
        }
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public String getKid() {
        return authProperties.getJwt().getKeyId();
    }
}
