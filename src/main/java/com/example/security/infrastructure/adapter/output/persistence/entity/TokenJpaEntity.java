package com.example.security.infrastructure.adapter.output.persistence.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "token")
public class TokenJpaEntity {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, length = 1000)
    private String token;
    private String tokenType;
    private String tokenCategory;
    private Long userId;
    private Instant expiresAt;
    private boolean isRevoked;
    private boolean isExpired;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public String getTokenCategory() { return tokenCategory; }
    public void setTokenCategory(String tokenCategory) { this.tokenCategory = tokenCategory; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isRevoked() { return isRevoked; }
    public void setRevoked(boolean revoked) { isRevoked = revoked; }
    public boolean isExpired() { return isExpired; }
    public void setExpired(boolean expired) { isExpired = expired; }
}
