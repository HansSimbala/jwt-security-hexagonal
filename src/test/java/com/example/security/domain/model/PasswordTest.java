package com.example.security.domain.model;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

@DisplayName("Password Value Object Tests")
class PasswordTest {

    @Nested
    @DisplayName("Valid Passwords")
    class ValidPasswords {
        @ParameterizedTest
        @ValueSource(strings = {"password123", "securePass1", "12345678"})
        @DisplayName("Should create valid password")
        void shouldCreateValidPassword(String value) {
            // Arrange - value provided
            // Act
            Password password = Password.ofPlainText(value);
            // Assert
            assertThat(password.getValue()).isEqualTo(value);
            assertThat(password.isHashed()).isFalse();
        }
    }

    @Nested
    @DisplayName("Invalid Passwords")
    class InvalidPasswords {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/invalid-passwords.csv", numLinesToSkip = 1)
        @DisplayName("Should reject invalid password")
        void shouldRejectInvalidPassword(String password, String expectedError) {
            // Arrange - provided by CSV
            // Act & Assert
            assertThatThrownBy(() -> Password.ofPlainText(password))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(expectedError);
        }
    }

    @Nested
    @DisplayName("Hashed Passwords")
    class HashedPasswords {
        @Test
        @DisplayName("Should create hashed password")
        void shouldCreateHashedPassword() {
            // Arrange
            String hashed = "$2a$10$abcdefghijklmnopqrstuvwxyz";
            // Act
            Password password = Password.ofHashed(hashed);
            // Assert
            assertThat(password.getValue()).isEqualTo(hashed);
            assertThat(password.isHashed()).isTrue();
        }
    }
}
