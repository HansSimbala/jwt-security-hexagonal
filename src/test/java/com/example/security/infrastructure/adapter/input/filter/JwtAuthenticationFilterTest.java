package com.example.security.infrastructure.adapter.input.filter;

import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Role;
import com.example.security.domain.model.Token;
import com.example.security.domain.model.User;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("JwtAuthenticationFilter Tests")
class JwtAuthenticationFilterTest {

    private final TokenGeneratorPort tokenGenerator = mock(TokenGeneratorPort.class);
    private final TokenRepositoryPort tokenRepository = mock(TokenRepositoryPort.class);
    private final JwtAuthenticationFilter filter =
            new JwtAuthenticationFilter(tokenGenerator, tokenRepository);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Request con token valido -> autenticado")
    void shouldAuthenticateWhenTokenValid() throws ServletException, IOException {
        // Arrange
        String token = "valid-token";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protected/me");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        User user = User.builder()
                .id(1L)
                .name("Juan")
                .email(Email.of("juan@example.com"))
                .password(Password.ofHashed("$2a$10$hashed"))
                .role(Role.CUSTOMER)
                .build();

        Token dbToken = Token.builder()
                .value(token)
                .category(Token.TokenCategory.ACCESS)
                .userId(1L)
                .expiresAt(Instant.now().plusSeconds(3600))
                .isRevoked(false)
                .isExpired(false)
                .build();

        when(tokenGenerator.extractUserId(token)).thenReturn(1L);
        when(tokenRepository.findByValue(token)).thenReturn(Optional.of(dbToken));
        when(tokenGenerator.isTokenValid(token)).thenReturn(true);
        when(tokenGenerator.extractRoles(token)).thenReturn(List.of("CUSTOMER"));
        when(tokenGenerator.extractScopes(token)).thenReturn(List.of("accounts:read"));

        // Act
        filter.doFilter(request, response, chain);

        // Assert
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(response.getStatus()).isNotEqualTo(401);
    }

    @Test
    @DisplayName("Request sin token -> no autenticado (continua)")
    void shouldContinueWithoutAuthenticationWhenTokenMissing() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protected/me");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        // Act
        filter.doFilter(request, response, chain);

        // Assert
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isNotEqualTo(401);
    }

    @Test
    @DisplayName("Request con token expirado -> 401")
    void shouldReturnUnauthorizedWhenTokenExpired() throws ServletException, IOException {
        // Arrange
        String token = "expired-token";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protected/me");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        Token dbToken = Token.builder()
                .value(token)
                .category(Token.TokenCategory.ACCESS)
                .userId(1L)
                .expiresAt(Instant.now().minusSeconds(1))
                .isRevoked(false)
                .isExpired(true)
                .build();

        when(tokenGenerator.extractUserId(token)).thenReturn(1L);
        when(tokenRepository.findByValue(token)).thenReturn(Optional.of(dbToken));

        // Act
        filter.doFilter(request, response, chain);

        // Assert
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("Request con token revocado -> 401")
    void shouldReturnUnauthorizedWhenTokenRevoked() throws ServletException, IOException {
        // Arrange
        String token = "revoked-token";
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protected/me");
        request.addHeader("Authorization", "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        Token dbToken = Token.builder()
                .value(token)
                .category(Token.TokenCategory.ACCESS)
                .userId(1L)
                .expiresAt(Instant.now().plusSeconds(3600))
                .isRevoked(true)
                .isExpired(false)
                .build();

        when(tokenGenerator.extractUserId(token)).thenReturn(1L);
        when(tokenRepository.findByValue(token)).thenReturn(Optional.of(dbToken));

        // Act
        filter.doFilter(request, response, chain);

        // Assert
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    @DisplayName("Request a endpoint publico -> no valida token")
    void shouldSkipValidationForPublicEndpoint() throws ServletException, IOException {
        // Arrange
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        // Act
        filter.doFilter(request, response, chain);

        // Assert
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getStatus()).isNotEqualTo(401);
    }
}
