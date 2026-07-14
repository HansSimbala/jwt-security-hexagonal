package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.infrastructure.adapter.output.persistence.TokenJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.UserJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.entity.UserJpaEntity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.main.allow-bean-definition-overriding=true",
                "rate-limit.enabled=true",
                "rate-limit.login.max-requests=20",
                "rate-limit.login.window-minutes=1",
                "rate-limit.register.max-requests=5",
                "rate-limit.register.window-minutes=60"
        })
@ActiveProfiles("test")
@DisplayName("RateLimitIntegrationTest")
class RateLimitIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired private UserJpaRepository userJpaRepository;
    @Autowired private TokenJpaRepository tokenJpaRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired @Qualifier("rateLimitClock") private MutableClock mutableClock;

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
    void setUp() {
        tokenJpaRepository.deleteAll();
        userJpaRepository.deleteAll();
        mutableClock.setInstant(Instant.parse("2026-03-23T00:00:00Z"));
    }

    @Test
    @DisplayName("Should allow 20 login requests per minute and block request 21")
    void shouldAllow20LoginsAndBlock21st() {
        for (int i = 1; i <= 20; i++) {
            ResponseEntity<Map> response = login("unknown-" + i + "@test.com", "wrong-password", "10.10.10.1");
            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertRateLimitHeadersPresent(response);
        }

        ResponseEntity<Map> blocked = login("unknown-21@test.com", "wrong-password", "10.10.10.1");
        assertThat(blocked.getStatusCode().value()).isEqualTo(429);
        assertThat(blocked.getHeaders().getFirst("X-RateLimit-Limit")).isEqualTo("20");
        assertThat(blocked.getHeaders().getFirst("X-RateLimit-Remaining")).isEqualTo("0");
    }

    @Test
    @DisplayName("Should allow 5 registrations per hour and block request 6")
    void shouldAllow5RegistrationsAndBlock6th() {
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<Map> response = register("reg" + i + "@test.com", "20.20.20.1");
            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertRateLimitHeadersPresent(response);
        }

        ResponseEntity<Map> blocked = register("reg6@test.com", "20.20.20.1");
        assertThat(blocked.getStatusCode().value()).isEqualTo(429);
        assertThat(blocked.getHeaders().getFirst("X-RateLimit-Limit")).isEqualTo("5");
    }

    @Test
    @DisplayName("Should track different IPs independently")
    void shouldTrackDifferentIpsIndependently() {
        for (int i = 1; i <= 5; i++) {
            ResponseEntity<Map> response = register("ip1-" + i + "@test.com", "30.30.30.1");
            assertThat(response.getStatusCode().value()).isEqualTo(201);
        }

        ResponseEntity<Map> blockedIp1 = register("ip1-6@test.com", "30.30.30.1");
        ResponseEntity<Map> ip2Allowed = register("ip2-1@test.com", "30.30.30.2");

        assertThat(blockedIp1.getStatusCode().value()).isEqualTo(429);
        assertThat(ip2Allowed.getStatusCode().value()).isEqualTo(201);
    }

    @Test
    @DisplayName("Should allow requests again after window expires")
    void shouldAllowRequestsAfterWindowExpires() {
        for (int i = 0; i < 20; i++) {
            ResponseEntity<Map> response = login("window-" + i + "@test.com", "wrong-password", "40.40.40.1");
            assertThat(response.getStatusCode().value()).isEqualTo(401);
        }

        ResponseEntity<Map> blocked = login("window-block@test.com", "wrong-password", "40.40.40.1");
        assertThat(blocked.getStatusCode().value()).isEqualTo(429);

        mutableClock.advanceSeconds(61);

        ResponseEntity<Map> allowedAfterReset = login("window-reset@test.com", "wrong-password", "40.40.40.1");
        assertThat(allowedAfterReset.getStatusCode().value()).isEqualTo(401);
    }

    @Test
    @DisplayName("Should work with brute force protection without conflicts")
    void shouldWorkWithBruteForceWithoutConflicts() {
        createUser("bruteforce-rate@test.com", "password123");

        for (int i = 0; i < 5; i++) {
            ResponseEntity<Map> failed = login("bruteforce-rate@test.com", "wrong-password", "50.50.50.1");
            assertThat(failed.getStatusCode().value()).isEqualTo(401);
        }

        ResponseEntity<Map> blockedByBruteForce = login("bruteforce-rate@test.com", "wrong-password", "50.50.50.1");
        assertThat(blockedByBruteForce.getStatusCode().value()).isEqualTo(429);
        if (blockedByBruteForce.getBody() != null && blockedByBruteForce.getBody().get("message") != null) {
            assertThat(blockedByBruteForce.getBody().get("message").toString())
                    .contains("Account temporarily locked");
        }
    }

    private void assertRateLimitHeadersPresent(ResponseEntity<Map> response) {
        assertThat(response.getHeaders().getFirst("X-RateLimit-Limit")).isNotBlank();
        assertThat(response.getHeaders().getFirst("X-RateLimit-Remaining")).isNotBlank();
        assertThat(response.getHeaders().getFirst("X-RateLimit-Reset")).isNotBlank();
    }

    private ResponseEntity<Map> login(String email, String password, String ip) {
        String payload = """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(email, password);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Forwarded-For", ip);

        return restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/login",
                new HttpEntity<>(payload, headers),
                Map.class);
    }

    private ResponseEntity<Map> register(String email, String ip) {
        String payload = """
                {
                  "name": "Rate User",
                  "email": "%s",
                  "password": "password123",
                  "role": "CUSTOMER"
                }
                """.formatted(email);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-Forwarded-For", ip);

        return restTemplate.postForEntity(
                "http://localhost:" + port + "/api/v1/auth/register",
                new HttpEntity<>(payload, headers),
                Map.class);
    }

    private void createUser(String email, String password) {
        UserJpaEntity user = new UserJpaEntity();
        user.setName("Rate User");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRole("CUSTOMER");
        userJpaRepository.save(user);
    }

    @TestConfiguration
    static class RateLimitTestClockConfig {
        @Bean
        @Qualifier("rateLimitClock")
        MutableClock rateLimitClock() {
            return new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        }
    }

    static class MutableClock extends Clock {
        private Instant instant;

        MutableClock(Instant instant) {
            this.instant = instant;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }

        void advanceSeconds(long seconds) {
            this.instant = this.instant.plusSeconds(seconds);
        }

        void setInstant(Instant instant) {
            this.instant = instant;
        }
    }
}
