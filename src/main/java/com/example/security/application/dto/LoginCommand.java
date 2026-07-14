package com.example.security.application.dto;

public record LoginCommand(String email, String password) {
    public LoginCommand {
        if (email == null || email.isBlank()) throw new IllegalArgumentException("Email is required");
        if (password == null || password.isBlank()) throw new IllegalArgumentException("Password is required");
    }
}
