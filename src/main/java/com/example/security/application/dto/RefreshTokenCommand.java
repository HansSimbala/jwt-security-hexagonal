package com.example.security.application.dto;

public record RefreshTokenCommand(String refreshToken) {
    public RefreshTokenCommand {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token is required");
        }
    }
}
