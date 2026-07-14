package com.example.security.application.dto;

public record TokenResult(String accessToken, String refreshToken, String tokenType, long expiresInSeconds) {
    public TokenResult {
        if (accessToken == null || accessToken.isBlank())
            throw new IllegalArgumentException("Access token is required");
        if (refreshToken == null || refreshToken.isBlank())
            throw new IllegalArgumentException("Refresh token is required");
    }

    public static TokenResult of(String accessToken, String refreshToken, long expiresInSeconds) {
        return new TokenResult(accessToken, refreshToken, "Bearer", expiresInSeconds);
    }
}
