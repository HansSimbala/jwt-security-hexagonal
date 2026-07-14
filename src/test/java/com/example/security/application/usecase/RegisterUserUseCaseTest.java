package com.example.security.application.usecase;

import com.example.security.application.dto.*;
import com.example.security.domain.exception.UserAlreadyExistsException;
import com.example.security.domain.model.*;
import com.example.security.domain.port.output.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("RegisterUserUseCase Tests")
class RegisterUserUseCaseTest {

    @Mock private UserRepositoryPort userRepository;
    @Mock private TokenRepositoryPort tokenRepository;
    @Mock private TokenGeneratorPort tokenGenerator;
    @Mock private PasswordEncoderPort passwordEncoder;
    @InjectMocks private RegisterUserUseCase useCase;

    @Nested
    @DisplayName("Successful Registration")
    class SuccessfulRegistration {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/valid-users.csv", numLinesToSkip = 1)
        @DisplayName("Should register user successfully")
        void shouldRegisterUser(String name, String email, String password, String role) {
            // Arrange
            RegisterCommand command = new RegisterCommand(name, email, password, role);
            when(userRepository.existsByEmail(any())).thenReturn(false);
            when(passwordEncoder.encode(any())).thenReturn(Password.ofHashed("$2a$hashed"));
            when(userRepository.save(any())).thenAnswer(inv -> ((User) inv.getArgument(0)).withId(1L));
            when(tokenGenerator.generateAccessToken(any())).thenReturn("access-token");
            when(tokenGenerator.generateRefreshToken(any())).thenReturn("refresh-token");
            when(tokenGenerator.getAccessTokenExpirationSeconds()).thenReturn(3600L);
            when(tokenGenerator.getRefreshTokenExpirationSeconds()).thenReturn(604800L);

            // Act
            TokenResult result = useCase.register(command);

            // Assert
            assertThat(result.accessToken()).isEqualTo("access-token");
            assertThat(result.refreshToken()).isEqualTo("refresh-token");
            assertThat(result.tokenType()).isEqualTo("Bearer");
            verify(userRepository).save(any(User.class));
            // verify(token...
        }
    }

    @Test
    @DisplayName("Should throw when user already exists")
    void shouldThrowWhenUserAlreadyExists() {
        RegisterCommand command = new RegisterCommand("Juan", "juan@example.com", "password123", "CUSTOMER");
        when(userRepository.existsByEmail(any())).thenReturn(true);
        assertThatThrownBy(() -> useCase.register(command))
            .isInstanceOf(UserAlreadyExistsException.class);
    }
}
