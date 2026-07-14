package com.example.security.integration;

import com.example.security.application.dto.RegisterCommand;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.infrastructure.adapter.output.persistence.TokenJpaRepository;
import com.example.security.infrastructure.adapter.output.persistence.UserJpaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.ClientHttpResponse;

import java.util.Map;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@DisplayName("OAuth Scope-Based Authorization Tests")
class AccountsControllerIntegrationTest {

    @LocalServerPort
    private int port;

    private final RestTemplate restTemplate = createRestTemplate();

    @Autowired
    private RegisterUserPort registerUserPort;

    @Autowired
    private UserJpaRepository userRepository;

    @Autowired
    private TokenJpaRepository tokenRepository;

    private String adminToken;
    private String tellerToken;
    private String customerToken;

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
        tokenRepository.deleteAll();
        userRepository.deleteAll();
        adminToken = registerAndGetToken("admin@example.com", "ADMIN");
        tellerToken = registerAndGetToken("teller@example.com", "TELLER");
        customerToken = registerAndGetToken("customer@example.com", "CUSTOMER");
    }

    @Nested
    @DisplayName("GET /api/v1/accounts - accounts:read scope")
    class ReadAccountsEndpoint {

        @Test
        @DisplayName("CUSTOMER should access with accounts:read scope")
        void customerCanReadAccounts() {
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.GET, "/api/v1/accounts", customerToken, null);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody().get("requiredScope")).isEqualTo("accounts:read");
        }

        @Test
        @DisplayName("TELLER should access with accounts:read scope")
        void tellerCanReadAccounts() {
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.GET, "/api/v1/accounts", tellerToken, null);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
        }

        @Test
        @DisplayName("ADMIN should access with accounts:read scope")
        void adminCanReadAccounts() {
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.GET, "/api/v1/accounts", adminToken, null);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
        }

        @Test
        @DisplayName("Unauthenticated user should get 401")
        void unauthenticatedCantAccess() {
            ResponseEntity<Map> response = exchangeWithoutToken(HttpMethod.GET, "/api/v1/accounts", null);
            assertThat(response.getStatusCode().value()).isEqualTo(401);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/accounts - accounts:write scope")
    class WriteAccountsEndpoint {

        @Test
        @DisplayName("CUSTOMER should be denied (lacks accounts:write scope)")
        void customerCantCreateAccount() {
            String json = "{\"name\":\"Cuenta Nueva\",\"initialBalance\":5000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts", customerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(403);
        }

        @Test
        @DisplayName("TELLER should create account (has accounts:write scope)")
        void tellerCanCreateAccount() {
            String json = "{\"name\":\"Cuenta Nueva\",\"initialBalance\":5000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts", tellerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertThat(response.getBody().get("name")).isEqualTo("Cuenta Nueva");
        }

        @Test
        @DisplayName("ADMIN should create account (has accounts:write scope)")
        void adminCanCreateAccount() {
            String json = "{\"name\":\"Cuenta Nueva\",\"initialBalance\":5000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts", adminToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(201);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/accounts/{id}/transfer - transfers:create scope")
    class TransfersEndpoint {

        @Test
        @DisplayName("CUSTOMER should be denied (lacks transfers:create scope)")
        void customerCantTransfer() {
            String json = "{\"toAccountId\":2,\"amount\":1000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/transfer", customerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(403);
        }

        @Test
        @DisplayName("TELLER should create transfer (has transfers:create scope)")
        void tellerCanTransfer() {
            String json = "{\"toAccountId\":2,\"amount\":1000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/transfer", tellerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody().get("requiredScope")).isEqualTo("transfers:create");
        }

        @Test
        @DisplayName("ADMIN should create transfer (has transfers:create scope)")
        void adminCanTransfer() {
            String json = "{\"toAccountId\":2,\"amount\":1000.00}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/transfer", adminToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
        }
    }

    @Nested
    @DisplayName("POST /api/v1/accounts/{id}/beneficiaries - beneficiaries:manage scope")
    class BeneficiariesEndpoint {

        @Test
        @DisplayName("CUSTOMER should be denied (lacks beneficiaries:manage scope)")
        void customerCantManageBeneficiaries() {
            String json = "{\"beneficiaryName\":\"Juan Pérez\",\"beneficiaryEmail\":\"juan@example.com\"}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/beneficiaries", customerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(403);
        }

        @Test
        @DisplayName("TELLER should be denied (lacks beneficiaries:manage scope)")
        void tellerCantManageBeneficiaries() {
            String json = "{\"beneficiaryName\":\"Juan Pérez\",\"beneficiaryEmail\":\"juan@example.com\"}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/beneficiaries", tellerToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(403);
        }

        @Test
        @DisplayName("ADMIN should manage beneficiaries (has beneficiaries:manage scope)")
        void adminCanManageBeneficiaries() {
            String json = "{\"beneficiaryName\":\"Juan Pérez\",\"beneficiaryEmail\":\"juan@example.com\"}";
            ResponseEntity<Map> response = exchangeWithToken(HttpMethod.POST, "/api/v1/accounts/1/beneficiaries", adminToken, json);
            assertThat(response.getStatusCode().value()).isEqualTo(201);
            assertThat(String.valueOf(response.getBody().get("requiredScope"))).contains("beneficiaries:manage");
        }
    }

    private ResponseEntity<Map> exchangeWithToken(HttpMethod method, String path, String token, String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + token);
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        return restTemplate.exchange("http://localhost:" + port + path, method, entity, Map.class);
    }

    private ResponseEntity<Map> exchangeWithoutToken(HttpMethod method, String path, String body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> entity = new HttpEntity<>(body, headers);
        return restTemplate.exchange("http://localhost:" + port + path, method, entity, Map.class);
    }

    private String registerAndGetToken(String email, String role) {
        var response = registerUserPort.register(new RegisterCommand(
                "User " + role,
                email,
                "password123",
                role
        ));
        return response.accessToken();
    }
}
