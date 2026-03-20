package com.example.auth.security;

import com.example.auth.config.AuthProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.security.PublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ExternalJwksServiceTest {

    private RestTemplate restTemplate;
    private ExternalJwksService externalJwksService;

    @BeforeEach
    void setUp() {
        restTemplate = mock(RestTemplate.class);
        AuthProperties properties = new AuthProperties();
        properties.getJwks().setCacheTtlMinutes(60);
        externalJwksService = new ExternalJwksService(restTemplate, new ObjectMapper(), properties);
    }

    @Test
    void shouldFetchAndReturnPublicKey() {
        String jwks = "{" +
                "\"keys\":[{" +
                "\"kty\":\"RSA\"," +
                "\"kid\":\"kid-1\"," +
                "\"n\":\"sXchf6Pj0wzA-9dFhOXQF0bfR2s6j0jrISFRCGDpa2BkLomqKgkl0vvArkH5AO9M1wAAuA5sif7mB9Q2RgxN6E3J6j_AvZEBtcHTul3e8DqRLVQjaxAgq6nxsVXni4eWh05rq6ArlTc95xJ3Adxpv8uKXuX4nHCqB6f0GO6zkRgBTAj39-C4R2tQeMgsQUK91tIbp-BKUKf5pFwchAuCdb9hirtmHg56k97X3CJidb8sRPzQIDdnh3oX1N1pAVccahJgN9zeps2sonMSKcwk5Y8ZndKyVKoU9pYNCXS6tlNZFwXk4Hknc0NrF4Pjk6HoydxHDBPPfQtbDNRsTA\"," +
                "\"e\":\"AQAB\"}]}";
        when(restTemplate.getForObject("http://mock/jwks", String.class)).thenReturn(jwks);

        PublicKey key = externalJwksService.findKey("http://mock/jwks", "kid-1");

        assertThat(key).isNotNull();
        verify(restTemplate, times(1)).getForObject("http://mock/jwks", String.class);
    }
}
