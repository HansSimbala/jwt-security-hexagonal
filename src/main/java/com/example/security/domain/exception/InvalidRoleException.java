package com.example.security.domain.exception;

public class InvalidRoleException extends RuntimeException {
    private final String role;

    public InvalidRoleException(String role) {
        super("Invalid role: " + role);
        this.role = role;
    }

    public String getRole() { return role; }
}
