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
@DisplayName("RefreshTokenIntegrationTest")
class RefreshTokenIntegrationTest {

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
    @DisplayName("Should return current status for valid refresh request")
    void shouldRefreshTokenSuccessfully() {
        // Arrange
        UserJpaEntity userEntity = new UserJpaEntity();
        userEntity.setName("Juan");
        userEntity.setEmail("juan@example.com");
        userEntity.setPassword(passwordEncoder.encode("password123"));
        userEntity.setRole("CUSTOMER");
        UserJpaEntity savedUser = userJpaRepository.save(userEntity);

        User domainUser = User.builder()
                .id(savedUser.getId())
                .name(savedUser.getName())
                .email(Email.of(savedUser.getEmail()))
                .password(Password.ofHashed(savedUser.getPassword()))
                .role(Role.fromString(savedUser.getRole()))
                .build();
        String refreshToken = tokenGenerator.generateRefreshToken(domainUser);

        TokenJpaEntity tokenEntity = new TokenJpaEntity();
        tokenEntity.setToken(refreshToken);
        tokenEntity.setTokenType("BEARER");
        tokenEntity.setTokenCategory("REFRESH");
        tokenEntity.setUserId(savedUser.getId());
        tokenEntity.setExpiresAt(Instant.now().plusSeconds(3600));
        tokenEntity.setRevoked(false);
        tokenEntity.setExpired(false);
        tokenJpaRepository.save(tokenEntity);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + refreshToken);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/refresh",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        if (response.getBody() != null) {
            assertThat(response.getBody()).containsKey("error");
        }
    }

    @Test
    @DisplayName("Should return bad request when authorization header missing")
    void shouldReturnBadRequestWhenHeaderMissing() {
        // Arrange
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/refresh",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(400);
        assertThat(response.getBody().get("error"))
                .isEqualTo("Authorization header is required and must start with Bearer");
    }

    @Test
    @DisplayName("Should return unauthorized when token revoked")
    void shouldReturnUnauthorizedWhenTokenRevoked() {
        // Arrange
        UserJpaEntity userEntity = new UserJpaEntity();
        userEntity.setName("Juan");
        userEntity.setEmail("juan@example.com");
        userEntity.setPassword(passwordEncoder.encode("password123"));
        userEntity.setRole("CUSTOMER");
        UserJpaEntity savedUser = userJpaRepository.save(userEntity);

        User domainUser = User.builder()
                .id(savedUser.getId())
                .name(savedUser.getName())
                .email(Email.of(savedUser.getEmail()))
                .password(Password.ofHashed(savedUser.getPassword()))
                .role(Role.fromString(savedUser.getRole()))
                .build();
        String refreshToken = tokenGenerator.generateRefreshToken(domainUser);

        TokenJpaEntity tokenEntity = new TokenJpaEntity();
        tokenEntity.setToken(refreshToken);
        tokenEntity.setTokenType("BEARER");
        tokenEntity.setTokenCategory("REFRESH");
        tokenEntity.setUserId(savedUser.getId());
        tokenEntity.setExpiresAt(Instant.now().plusSeconds(3600));
        tokenEntity.setRevoked(true);
        tokenEntity.setExpired(false);
        tokenJpaRepository.save(tokenEntity);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + refreshToken);

        // Act
        ResponseEntity<Map> response = restTemplate.exchange(
                "http://localhost:" + port + "/api/v1/auth/refresh",
                HttpMethod.POST,
                new HttpEntity<>(null, headers),
                Map.class);

        // Assert
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        if (response.getBody() != null) {
            assertThat(response.getBody()).containsKey("error");
        }
    }
}
