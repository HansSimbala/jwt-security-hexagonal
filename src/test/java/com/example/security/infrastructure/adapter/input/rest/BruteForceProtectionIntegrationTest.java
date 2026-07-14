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
@DisplayName("BruteForceProtectionIntegrationTest")
class BruteForceProtectionIntegrationTest {

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
    @DisplayName("Should block account after 5 failed login attempts")
    void shouldBlockAccountAfterFiveFailedAttempts() {
        createUser("blocked@test.com", "correctPassword");

        for (int i = 0; i < 5; i++) {
            ResponseEntity<Map> failedLogin = login("blocked@test.com", "wrongPassword");
            assertThat(failedLogin.getStatusCode().value()).isEqualTo(401);
        }

        ResponseEntity<Map> blockedLogin = login("blocked@test.com", "wrongPassword");

        assertThat(blockedLogin.getStatusCode().value()).isEqualTo(429);
        assertThat(blockedLogin.getBody().get("error")).isEqualTo("Too Many Requests");
        assertThat(blockedLogin.getBody().get("message").toString())
                .contains("Account temporarily locked due to multiple failed login attempts");
    }

    @Test
    @DisplayName("Should reset attempts after successful login")
    void shouldResetAttemptsAfterSuccessfulLogin() {
        createUser("reset@test.com", "correctPassword");

        ResponseEntity<Map> firstFail = login("reset@test.com", "wrongPassword");
        ResponseEntity<Map> secondFail = login("reset@test.com", "wrongPassword");
        ResponseEntity<Map> success = login("reset@test.com", "correctPassword");
        ResponseEntity<Map> failAfterSuccess = login("reset@test.com", "wrongPassword");

        assertThat(firstFail.getStatusCode().value()).isEqualTo(401);
        assertThat(secondFail.getStatusCode().value()).isEqualTo(401);
        assertThat(success.getStatusCode().value()).isEqualTo(200);
        assertThat(failAfterSuccess.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Should keep counters independent by user")
    void shouldKeepCountersIndependentByUser() {
        createUser("user1@test.com", "correctPassword");
        createUser("user2@test.com", "correctPassword");

        for (int i = 0; i < 5; i++) {
            ResponseEntity<Map> user1FailedLogin = login("user1@test.com", "wrongPassword");
            assertThat(user1FailedLogin.getStatusCode().value()).isEqualTo(401);
        }

        ResponseEntity<Map> user1Blocked = login("user1@test.com", "wrongPassword");
        ResponseEntity<Map> user2FirstFail = login("user2@test.com", "wrongPassword");

        assertThat(user1Blocked.getStatusCode().value()).isEqualTo(429);
        assertThat(user2FirstFail.getStatusCode().value()).isEqualTo(401);
    }

    private void createUser(String email, String password) {
        UserJpaEntity user = new UserJpaEntity();
        user.setName("Test User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("CUSTOMER");
        userJpaRepository.save(user);
    }

    private ResponseEntity<Map> login(String email, String password) {
        String payload = """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(email, password);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        return restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/login",
                new HttpEntity<>(payload, headers),
                Map.class);
    }
}
