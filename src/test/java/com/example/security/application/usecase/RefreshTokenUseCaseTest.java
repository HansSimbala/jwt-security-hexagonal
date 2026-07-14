package com.example.security.application.usecase;

import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Role;
import com.example.security.domain.model.Token;
import com.example.security.domain.model.User;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import com.example.security.domain.port.output.UserRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenUseCase Tests")
class RefreshTokenUseCaseTest {

    @Mock private UserRepositoryPort userRepository;
    @Mock private TokenRepositoryPort tokenRepository;
    @Mock private TokenGeneratorPort tokenGenerator;
    @InjectMocks private RefreshTokenUseCase useCase;

    @Nested
    @DisplayName("Successful refresh")
    class SuccessfulRefresh {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/valid-refresh-tokens.csv", numLinesToSkip = 1)
        @DisplayName("Should refresh tokens successfully")
        void shouldRefreshSuccessfully(String refreshToken, Long userId) {
            // Arrange
            Token storedToken = Token.builder()
                    .id(10L)
                    .value(refreshToken)
                    .category(Token.TokenCategory.REFRESH)
                    .userId(userId)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .isRevoked(false)
                    .isExpired(false)
                    .build();
            User user = User.builder()
                    .id(userId)
                    .name("User")
                    .email(Email.of("user" + userId + "@example.com"))
                    .password(Password.ofHashed("$2a$10$hashed"))
                    .role(Role.CUSTOMER)
                    .build();

            when(tokenRepository.findByValue(refreshToken)).thenReturn(Optional.of(storedToken));
            when(tokenGenerator.isTokenValid(refreshToken)).thenReturn(true);
            when(tokenGenerator.extractUserId(refreshToken)).thenReturn(userId);
            when(userRepository.findById(userId)).thenReturn(Optional.of(user));
            when(tokenGenerator.generateAccessToken(user)).thenReturn("new-access-token");
            when(tokenGenerator.generateRefreshToken(user)).thenReturn("new-refresh-token");
            when(tokenGenerator.getAccessTokenExpirationSeconds()).thenReturn(3600L);
            when(tokenGenerator.getRefreshTokenExpirationSeconds()).thenReturn(604800L);

            // Act
            TokenResult result = useCase.refresh(refreshToken);

            // Assert
            assertThat(result.accessToken()).isEqualTo("new-access-token");
            assertThat(result.refreshToken()).isEqualTo("new-refresh-token");
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresInSeconds()).isEqualTo(3600L);
            verify(tokenRepository).revokeAllUserTokens(userId);
            verify(tokenRepository, times(2)).save(any(Token.class));
        }
    }

    @Nested
    @DisplayName("Invalid refresh")
    class InvalidRefresh {
        @Test
        @DisplayName("Should fail when token not found")
        void shouldFailWhenTokenNotFound() {
            // Arrange
            when(tokenRepository.findByValue("missing-token")).thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> useCase.refresh("missing-token"))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid token");
        }

        @Test
        @DisplayName("Should fail when token is revoked")
        void shouldFailWhenTokenIsRevoked() {
            // Arrange
            Token revokedToken = Token.builder()
                    .value("revoked-token")
                    .category(Token.TokenCategory.REFRESH)
                    .userId(1L)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .isRevoked(true)
                    .isExpired(false)
                    .build();
            when(tokenRepository.findByValue("revoked-token")).thenReturn(Optional.of(revokedToken));

            // Act & Assert
            assertThatThrownBy(() -> useCase.refresh("revoked-token"))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid token");
        }

        @Test
        @DisplayName("Should fail when token is expired")
        void shouldFailWhenTokenIsExpired() {
            // Arrange
            Token expiredToken = Token.builder()
                    .value("expired-token")
                    .category(Token.TokenCategory.REFRESH)
                    .userId(1L)
                    .expiresAt(Instant.now().minusSeconds(1))
                    .isRevoked(false)
                    .isExpired(true)
                    .build();
            when(tokenRepository.findByValue("expired-token")).thenReturn(Optional.of(expiredToken));

            // Act & Assert
            assertThatThrownBy(() -> useCase.refresh("expired-token"))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid token");
        }

        @Test
        @DisplayName("Should fail when user not found")
        void shouldFailWhenUserNotFound() {
            // Arrange
            String refreshToken = "valid-refresh-token";
            Token storedToken = Token.builder()
                    .value(refreshToken)
                    .category(Token.TokenCategory.REFRESH)
                    .userId(99L)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .isRevoked(false)
                    .isExpired(false)
                    .build();
            when(tokenRepository.findByValue(refreshToken)).thenReturn(Optional.of(storedToken));
            when(tokenGenerator.isTokenValid(refreshToken)).thenReturn(true);
            when(tokenGenerator.extractUserId(refreshToken)).thenReturn(99L);
            when(userRepository.findById(99L)).thenReturn(Optional.empty());

            // Act & Assert
            assertThatThrownBy(() -> useCase.refresh(refreshToken))
                    .isInstanceOf(InvalidTokenException.class)
                    .hasMessageContaining("Invalid token");
        }
    }
}
