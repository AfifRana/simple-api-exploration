package com.example.auth.integration;

import com.example.auth.security.ExternalTokenValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.notNullValue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ExternalTokenValidator externalTokenValidator;

    @Test
    void shouldSignupLoginAndGetMe() throws Exception {
        mockMvc.perform(post("/api/v1/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"it@example.com\",\"password\":\"Password123!\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("it@example.com"));

        String loginResponse = mockMvc.perform(post("/api/v1/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"it@example.com\",\"password\":\"Password123!\",\"deviceInfo\":\"it\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String token = loginResponse.replaceAll(".*\"accessToken\":\"([^\"]+)\".*", "$1");

        mockMvc.perform(get("/api/v1/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("it@example.com"));
    }

    @Test
    void shouldExposeStaticJwks() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid", notNullValue()));
    }

    @Test
    void shouldSocialLoginWithMockedExternalValidation() throws Exception {
        ExternalTokenValidator.ExternalPrincipal principal = new ExternalTokenValidator.ExternalPrincipal(
                "social@example.com",
                "sub-1",
                "google",
                null
        );
        when(externalTokenValidator.validate(anyString(), anyString())).thenReturn(principal);

        mockMvc.perform(post("/api/v1/login/social")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"provider\":\"google\",\"idToken\":\"dummy\",\"deviceInfo\":\"it\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken", notNullValue()))
                .andExpect(jsonPath("$.refreshToken", notNullValue()));
    }
}
