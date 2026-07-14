package com.example.security.domain.model;

import java.time.Instant;
import java.util.Objects;

public class Token {
    public enum TokenType { BEARER }
    public enum TokenCategory { ACCESS, REFRESH }

    private final Long id;
    private final String value;
    private final TokenType type;
    private final TokenCategory category;
    private final Long userId;
    private final Instant expiresAt;
    private boolean isRevoked;
    private boolean isExpired;

    private Token(Builder builder) {
        this.id = builder.id;
        this.value = builder.value;
        this.type = builder.type;
        this.category = builder.category;
        this.userId = builder.userId;
        this.expiresAt = builder.expiresAt;
        this.isRevoked = builder.isRevoked;
        this.isExpired = builder.isExpired;
    }

    public Long getId() { return id; }
    public String getValue() { return value; }
    public TokenType getType() { return type; }
    public TokenCategory getCategory() { return category; }
    public Long getUserId() { return userId; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return isRevoked; }
    public boolean isExpired() { return isExpired; }

    public void revoke() { this.isRevoked = true; }
    public void markAsExpired() { this.isExpired = true; }
    public boolean isValid() { return !isRevoked && !isExpired && Instant.now().isBefore(expiresAt); }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Long id;
        private String value;
        private TokenType type = TokenType.BEARER;
        private TokenCategory category = TokenCategory.ACCESS;
        private Long userId;
        private Instant expiresAt;
        private boolean isRevoked = false;
        private boolean isExpired = false;

        public Builder id(Long id) { this.id = id; return this; }
        public Builder value(String value) { this.value = value; return this; }
        public Builder type(TokenType type) { this.type = type; return this; }
        public Builder category(TokenCategory category) { this.category = category; return this; }
        public Builder userId(Long userId) { this.userId = userId; return this; }
        public Builder expiresAt(Instant expiresAt) { this.expiresAt = expiresAt; return this; }
        public Builder isRevoked(boolean isRevoked) { this.isRevoked = isRevoked; return this; }
        public Builder isExpired(boolean isExpired) { this.isExpired = isExpired; return this; }

        public Token build() {
            Objects.requireNonNull(value, "Token value is required");
            Objects.requireNonNull(userId, "User ID is required");
            Objects.requireNonNull(expiresAt, "Expiration is required");
            return new Token(this);
        }
    }
}
