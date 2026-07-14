package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.infrastructure.adapter.output.persistence.TokenJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.UserJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.entity.UserJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpResponse;
import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@DisplayName("LoginUserIntegrationTest")
class LoginUserIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestTemplate restTemplate = createRestTemplate();
    @Autowired private UserJpaRepository userJpaRepository;
    @Autowired private TokenJpaRepository tokenJpaRepository;
    @Autowired private PasswordEncoder passwordEncoder;

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
    void setUp() {
        tokenJpaRepository.deleteAll();
        userJpaRepository.deleteAll();
    }

    @Test
    @DisplayName("Should login successfully with valid credentials")
    void shouldLoginSuccessfully() throws Exception {
        // Arrange
        UserJpaEntity user = new UserJpaEntity();
        user.setName("Juan Perez");
        user.setEmail("juan@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole("CUSTOMER");
        userJpaRepository.save(user);

        String payload = """
                {
                  "email": "juan@example.com",
                  "password": "password123"
                }
                """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act & Assert
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/login",
                new HttpEntity<>(payload, headers),
                Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsKeys("access_token", "refresh_token", "token_type", "expires_in");
        assertThat(response.getBody().get("token_type")).isEqualTo("Bearer");
    }

    @Test
    @DisplayName("Should return unauthorized for invalid credentials")
    void shouldReturnUnauthorizedForInvalidCredentials() throws Exception {
        // Arrange
        UserJpaEntity user = new UserJpaEntity();
        user.setName("Juan Perez");
        user.setEmail("juan@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setRole("CUSTOMER");
        userJpaRepository.save(user);

        String payload = """
                {
                  "email": "juan@example.com",
                  "password": "wrongpassword"
                }
                """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act & Assert
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/login",
                new HttpEntity<>(payload, headers),
                Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody().get("error")).isEqualTo("Invalid credentials");
    }

    @Test
    @DisplayName("Should return bad request for empty fields")
    void shouldReturnBadRequestForEmptyFields() throws Exception {
        // Arrange
        String payload = """
                {
                  "email": "",
                  "password": ""
                }
                """;
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act & Assert
        ResponseEntity<Map> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/login",
                new HttpEntity<>(payload, headers),
                Map.class);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody().get("email")).isEqualTo("Email is required");
        assertThat(response.getBody().get("password")).isEqualTo("Password is required");
    }
}
