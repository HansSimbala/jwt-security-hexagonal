package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.application.dto.RegisterCommand;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.infrastructure.adapter.output.persistence.TokenJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.entity.TokenJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@DisplayName("LogoutIntegrationTest")
class LogoutIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private RegisterUserPort registerUserPort;

    @Autowired
    private TokenJpaRepository tokenJpaRepository;

    private final RestTemplate restTemplate = createRestTemplate();

    private RestTemplate createRestTemplate() {
        RestTemplate template = new RestTemplate();
        template.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return false;
            }
        });
        return template;
    }

    @BeforeEach
    void setup() {
        tokenJpaRepository.deleteAll();
    }

    @Test
    @DisplayName("POST /logout con token válido -> 200 OK")
    void shouldLogoutWithValidToken() {
        // Arrange
        String token = registerAndGetAccessToken("logout-valid@example.com", "CUSTOMER");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + token);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/logout",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().get("message")).isEqualTo("Logout successful");
        TokenJpaEntity persisted = tokenJpaRepository.findByToken(token).orElseThrow();
        assertThat(persisted.isRevoked()).isTrue();
        assertThat(persisted.isExpired()).isTrue();
    }

    @Test
    @DisplayName("POST /logout sin header Authorization -> 401")
    void shouldReturn401WhenAuthorizationMissing() {
        // Arrange
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/logout",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("POST /logout con token inválido -> 401")
    void shouldReturn401WithInvalidToken() {
        // Arrange
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer invalid.token.value");

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/logout",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Token revocado no funciona en siguiente request protegido")
    void shouldNotAllowRevokedTokenOnNextRequest() {
        // Arrange
        String token = registerAndGetAccessToken("logout-revoked@example.com", "CUSTOMER");

        HttpHeaders logoutHeaders = new HttpHeaders();
        logoutHeaders.setContentType(MediaType.APPLICATION_JSON);
        logoutHeaders.set("Authorization", "Bearer " + token);
        restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/logout",
                HttpMethod.POST,
                new HttpEntity<>(null, logoutHeaders),
                Map.class);

        HttpHeaders protectedHeaders = new HttpHeaders();
        protectedHeaders.setContentType(MediaType.APPLICATION_JSON);
        protectedHeaders.set("Authorization", "Bearer " + token);

        // Act
        ResponseEntity<Map> protectedResponse = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/protected/me",
                HttpMethod.GET,
                new HttpEntity<>(null, protectedHeaders),
                Map.class);

        // Assert
        assertThat(protectedResponse.getStatusCode().value()).isEqualTo(401);
    }

    private String registerAndGetAccessToken(String email, String role) {
        var response = registerUserPort.register(new RegisterCommand(
                "User " + role,
                email,
                "password123",
                role
        ));
        return response.accessToken();
    }
}
