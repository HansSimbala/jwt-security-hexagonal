package com.example.security.application.dto;

public record RegisterCommand(String name, String email, String password, String role) {
    public RegisterCommand {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Name is required");
        if (email == null || email.isBlank()) throw new IllegalArgumentException("Email is required");
        if (password == null || password.isBlank()) throw new IllegalArgumentException("Password is required");
        if (role == null || role.isBlank()) throw new IllegalArgumentException("Role is required");
    }
}
