package com.example.security.application.usecase;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.AccountLockedException;
import com.example.security.domain.exception.InvalidCredentialsException;
import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Role;
import com.example.security.domain.model.User;
import com.example.security.domain.port.output.LoginAttemptPort;
import com.example.security.domain.port.output.PasswordEncoderPort;
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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("LoginUserUseCase Tests")
class LoginUserUseCaseTest {

    @Mock private UserRepositoryPort userRepository;
    @Mock private TokenRepositoryPort tokenRepository;
    @Mock private TokenGeneratorPort tokenGenerator;
    @Mock private PasswordEncoderPort passwordEncoder;
    @Mock private LoginAttemptPort loginAttemptPort;
    @InjectMocks private LoginUserUseCase useCase;

    @Nested
    @DisplayName("Successful Login")
    class SuccessfulLogin {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/valid-logins.csv", numLinesToSkip = 1)
        @DisplayName("Should login user successfully")
        void shouldLoginUserSuccessfully(String email, String password) {
            // Arrange
            LoginCommand command = new LoginCommand(email, password);
            User user = User.builder()
                    .id(1L)
                    .name("Test User")
                    .email(Email.of(email))
                    .password(Password.ofHashed("$2a$10$hashed-password"))
                    .role(Role.CUSTOMER)
                    .build();
            when(userRepository.findByEmail(Email.of(email))).thenReturn(Optional.of(user));
            when(passwordEncoder.matches(any(), any())).thenReturn(true);
            when(tokenGenerator.generateAccessToken(user)).thenReturn("access-token");
            when(tokenGenerator.generateRefreshToken(user)).thenReturn("refresh-token");
            when(tokenGenerator.getAccessTokenExpirationSeconds()).thenReturn(3600L);
            when(tokenGenerator.getRefreshTokenExpirationSeconds()).thenReturn(604800L);
            when(loginAttemptPort.isBlocked(email)).thenReturn(false);

            // Act
            TokenResult result = useCase.login(command);

            // Assert
            assertThat(result.accessToken()).isEqualTo("access-token");
            assertThat(result.refreshToken()).isEqualTo("refresh-token");
            assertThat(result.tokenType()).isEqualTo("Bearer");
            assertThat(result.expiresInSeconds()).isEqualTo(3600L);
            verify(tokenRepository).revokeAllUserTokens(1L);
            verify(tokenRepository, times(2)).save(any());
            verify(loginAttemptPort).loginSucceeded(email);
            verify(loginAttemptPort, never()).loginFailed(any());
        }
    }

    @Nested
    @DisplayName("Invalid Credentials")
    class InvalidCredentials {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/invalid-logins.csv", numLinesToSkip = 1)
        @DisplayName("Should reject invalid credentials")
        void shouldRejectInvalidCredentials(String email, String password, String expectedError) {
            // Arrange
            LoginCommand command = new LoginCommand(email, password);

            if ("wrong@example.com".equals(email)) {
                when(userRepository.findByEmail(Email.of(email))).thenReturn(Optional.empty());
            } else {
                User user = User.builder()
                        .id(1L)
                        .name("Test User")
                        .email(Email.of(email))
                        .password(Password.ofHashed("$2a$10$hashed-password"))
                        .role(Role.CUSTOMER)
                        .build();
                when(userRepository.findByEmail(Email.of(email))).thenReturn(Optional.of(user));
                when(passwordEncoder.matches(any(), any())).thenReturn(false);
            }
            when(loginAttemptPort.isBlocked(email)).thenReturn(false);

            // Act & Assert
            assertThatThrownBy(() -> useCase.login(command))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessageContaining(expectedError);
            verify(loginAttemptPort).loginFailed(email);
            verify(loginAttemptPort, never()).loginSucceeded(any());
        }

        @Test
        @DisplayName("Should reject empty email")
        void shouldRejectEmptyEmail() {
            // Arrange & Act & Assert
            assertThatThrownBy(() -> new LoginCommand("", "password123"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Email is required");
        }

        @Test
        @DisplayName("Should reject empty password")
        void shouldRejectEmptyPassword() {
            // Arrange & Act & Assert
            assertThatThrownBy(() -> new LoginCommand("juan@example.com", ""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Password is required");
        }
    }

    @Test
    @DisplayName("Should reject login when account is blocked")
    void shouldRejectLoginWhenAccountIsBlocked() {
        // Arrange
        String email = "locked@example.com";
        LoginCommand command = new LoginCommand(email, "password123");
        when(loginAttemptPort.isBlocked(email)).thenReturn(true);

        // Act & Assert
        assertThatThrownBy(() -> useCase.login(command))
                .isInstanceOf(AccountLockedException.class)
                .hasMessageContaining("Account temporarily locked");

        verify(loginAttemptPort, never()).loginFailed(any());
        verify(loginAttemptPort, never()).loginSucceeded(any());
        verify(userRepository, never()).findByEmail(any());
    }

    @Test
    @DisplayName("Should reset attempts after successful login")
    void shouldResetAttemptsAfterSuccessfulLogin() {
        // Arrange
        String email = "juan@example.com";
        LoginCommand command = new LoginCommand(email, "password123");
        User user = User.builder()
                .id(1L)
                .name("Test User")
                .email(Email.of(email))
                .password(Password.ofHashed("$2a$10$hashed-password"))
                .role(Role.CUSTOMER)
                .build();
        when(loginAttemptPort.isBlocked(email)).thenReturn(false);
        when(userRepository.findByEmail(Email.of(email))).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(any(), any())).thenReturn(true);
        when(tokenGenerator.generateAccessToken(user)).thenReturn("access-token");
        when(tokenGenerator.generateRefreshToken(user)).thenReturn("refresh-token");
        when(tokenGenerator.getAccessTokenExpirationSeconds()).thenReturn(3600L);
        when(tokenGenerator.getRefreshTokenExpirationSeconds()).thenReturn(604800L);

        // Act
        useCase.login(command);

        // Assert
        verify(loginAttemptPort).loginSucceeded(eq(email));
        verify(loginAttemptPort, never()).loginFailed(any());
    }
}
