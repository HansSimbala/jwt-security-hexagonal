package com.example.security.domain.model;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

@DisplayName("Email Value Object Tests")
class EmailTest {

    @Nested
    @DisplayName("Valid Emails")
    class ValidEmails {
        @ParameterizedTest
        @ValueSource(strings = {"test@example.com", "user@domain.co.uk", "name+tag@test.org"})
        @DisplayName("Should create valid email")
        void shouldCreateValidEmail(String value) {
            // Arrange - value provided
            // Act
            Email email = Email.of(value);
            // Assert
            assertThat(email.getValue()).isEqualTo(value.toLowerCase());
        }

        @Test
        @DisplayName("Should be equal for same value")
        void shouldBeEqualForSameValue() {
            // Arrange
            String value = "test@example.com";
            // Act
            Email email1 = Email.of(value);
            Email email2 = Email.of(value);
            // Assert
            assertThat(email1).isEqualTo(email2);
            assertThat(email1.hashCode()).isEqualTo(email2.hashCode());
        }
    }

    @Nested
    @DisplayName("Invalid Emails")
    class InvalidEmails {
        @ParameterizedTest
        @CsvFileSource(resources = "/testdata/invalid-emails.csv", numLinesToSkip = 1)
        @DisplayName("Should reject invalid email")
        void shouldRejectInvalidEmail(String email, String expectedError) {
            // Arrange - provided by CSV
            // Act & Assert
            assertThatThrownBy(() -> Email.of(email))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(expectedError);
        }

        @Test
        @DisplayName("Should reject null email")
        void shouldRejectNullEmail() {
            // Arrange
            String nullEmail = null;
            // Act & Assert
            assertThatThrownBy(() -> Email.of(nullEmail))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be null");
        }
    }
}
