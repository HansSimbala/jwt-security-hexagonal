package com.example.security.domain.model;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.*;

@DisplayName("Role Enum Tests")
class RoleTest {

    @Nested
    @DisplayName("Role.fromString")
    class FromString {
        @ParameterizedTest
        @CsvSource({"ADMIN,ADMIN", "admin,ADMIN", "TELLER,TELLER", "customer,CUSTOMER"})
        @DisplayName("Should parse valid role string")
        void shouldParseValidRole(String input, Role expected) {
            // Arrange - provided
            // Act
            Role result = Role.fromString(input);
            // Assert
            assertThat(result).isEqualTo(expected);
        }

        @ParameterizedTest
        @ValueSource(strings = {"INVALID", "SUPERADMIN", "USER"})
        @DisplayName("Should reject invalid role")
        void shouldRejectInvalidRole(String invalidRole) {
            // Arrange - provided
            // Act & Assert
            assertThatThrownBy(() -> Role.fromString(invalidRole))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid role");
        }
    }

    @Nested
    @DisplayName("Role Permissions")
    class RolePermissions {
        @Test
        @DisplayName("ADMIN should have all permissions")
        void adminShouldHaveAllPermissions() {
            // Arrange
            Role admin = Role.ADMIN;
            // Act
            var permissions = admin.getPermissions();
            // Assert
            assertThat(permissions).hasSize(4);
            assertThat(permissions).contains(Permission.ACCOUNTS_READ, Permission.BENEFICIARIES_MANAGE);
        }

        @Test
        @DisplayName("CUSTOMER should have only read permission")
        void customerShouldHaveOnlyReadPermission() {
            // Arrange
            Role customer = Role.CUSTOMER;
            // Act
            var permissions = customer.getPermissions();
            // Assert
            assertThat(permissions).hasSize(1);
            assertThat(permissions).containsExactly(Permission.ACCOUNTS_READ);
        }
    }
}
