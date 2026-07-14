package com.example.security.domain.model;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public enum Role {
    ADMIN(Arrays.asList(
            Permission.ACCOUNTS_READ, Permission.ACCOUNTS_WRITE,
            Permission.TRANSFERS_CREATE, Permission.BENEFICIARIES_MANAGE)),
    TELLER(Arrays.asList(
            Permission.ACCOUNTS_READ, Permission.ACCOUNTS_WRITE, Permission.TRANSFERS_CREATE)),
    CUSTOMER(List.of(Permission.ACCOUNTS_READ));

    private final List<Permission> permissions;

    Role(List<Permission> permissions) {
        this.permissions = Collections.unmodifiableList(permissions);
    }

    public List<Permission> getPermissions() { return permissions; }

    public static Role fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Role cannot be null or empty");
        }
        try {
            return Role.valueOf(value.toUpperCase().trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid role: " + value);
        }
    }
}
