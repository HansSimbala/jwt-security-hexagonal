package com.example.security.application.dto;

public record LogoutCommand(String token) {
    public LogoutCommand {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token is required");
        }
    }
}
