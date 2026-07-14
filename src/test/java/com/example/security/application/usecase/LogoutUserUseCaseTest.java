package com.example.security.application.usecase;

import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.model.Token;
import com.example.security.domain.port.output.TokenRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("LogoutUserUseCase Tests")
class LogoutUserUseCaseTest {

    @Mock
    private TokenRepositoryPort tokenRepository;

    @InjectMocks
    private LogoutUserUseCase useCase;

    @Test
    @DisplayName("Logout exitoso - token encontrado y revocado")
    void shouldLogoutSuccessfullyWhenTokenExists() {
        // Arrange
        Token token = Token.builder()
                .id(1L)
                .value("valid-token")
                .userId(1L)
                .expiresAt(Instant.now().plusSeconds(3600))
                .isRevoked(false)
                .isExpired(false)
                .build();
        when(tokenRepository.findByValue("valid-token")).thenReturn(Optional.of(token));

        // Act
        useCase.logout("valid-token");

        // Assert
        verify(tokenRepository).revoke(token);
    }

    @Test
    @DisplayName("Logout falla - token no encontrado")
    void shouldFailWhenTokenNotFound() {
        // Arrange
        when(tokenRepository.findByValue("missing-token")).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> useCase.logout("missing-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Token not found");
    }

    @Test
    @DisplayName("Logout falla - token ya revocado")
    void shouldFailWhenTokenAlreadyRevoked() {
        // Arrange
        Token token = Token.builder()
                .id(1L)
                .value("revoked-token")
                .userId(1L)
                .expiresAt(Instant.now().plusSeconds(3600))
                .isRevoked(true)
                .isExpired(false)
                .build();
        when(tokenRepository.findByValue("revoked-token")).thenReturn(Optional.of(token));

        // Act & Assert
        assertThatThrownBy(() -> useCase.logout("revoked-token"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Nested
    @DisplayName("LogoutAll")
    class LogoutAll {
        @Test
        @DisplayName("Revoca todos los tokens del usuario")
        void shouldRevokeAllByUserId() {
            // Act
            useCase.logoutAll(10L);

            // Assert
            verify(tokenRepository).revokeAllByUserId(10L);
        }
    }
}
