package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Role;
import com.example.security.domain.model.User;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.infrastructure.adapter.output.persistence.TokenJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.UserJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.entity.TokenJpaEntity;
import com.example.security.infrastructure.adapter.output.persistence.entity.UserJpaEntity;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpResponse;

import java.time.Instant;
import java.util.Map;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@DisplayName("ProtectedEndpointIntegrationTest")
class ProtectedEndpointIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestTemplate restTemplate = createRestTemplate();
    @Autowired private UserJpaRepository userJpaRepository;
    @Autowired private TokenJpaRepository tokenJpaRepository;
    @Autowired private TokenGeneratorPort tokenGenerator;
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
    @DisplayName("GET protected con token valido -> 200")
    void shouldReturn200WithValidToken() {
        // Arrange
        UserJpaEntity userEntity = new UserJpaEntity();
        userEntity.setName("Juan");
        userEntity.setEmail("juan@example.com");
        userEntity.setPassword(passwordEncoder.encode("password123"));
        userEntity.setRole("CUSTOMER");
        UserJpaEntity savedUser = userJpaRepository.save(userEntity);

        User user = User.builder()
                .id(savedUser.getId())
                .name(savedUser.getName())
                .email(Email.of(savedUser.getEmail()))
                .password(Password.ofHashed(savedUser.getPassword()))
                .role(Role.fromString(savedUser.getRole()))
                .build();
        String accessToken = tokenGenerator.generateAccessToken(user);

        TokenJpaEntity tokenEntity = new TokenJpaEntity();
        tokenEntity.setToken(accessToken);
        tokenEntity.setTokenType("BEARER");
        tokenEntity.setTokenCategory("ACCESS");
        tokenEntity.setUserId(savedUser.getId());
        tokenEntity.setExpiresAt(Instant.now().plusSeconds(3600));
        tokenEntity.setRevoked(false);
        tokenEntity.setExpired(false);
        tokenJpaRepository.save(tokenEntity);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + accessToken);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/protected/me",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).containsKey("principal");
    }

    @Test
    @DisplayName("GET protected sin token -> 401")
    void shouldReturn401WithoutToken() {
        // Arrange
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/protected/me",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        if (response.getBody() != null) {
            assertThat(response.getBody().get("error")).isEqualTo("Unauthorized");
        }
    }

    @Test
    @DisplayName("GET protected con token invalido -> 401")
    void shouldReturn401WithInvalidToken() {
        // Arrange
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer invalid-token");

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/protected/me",
                HttpMethod.GET,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        if (response.getBody() != null) {
            assertThat(response.getBody().get("error")).isEqualTo("Token is invalid or expired");
        }
    }
}
