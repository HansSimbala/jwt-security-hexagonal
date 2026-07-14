package com.example.security.infrastructure.adapter.output.security;

import com.example.security.domain.model.User;
import com.example.security.domain.port.output.TokenGeneratorPort;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtTokenAdapter implements TokenGeneratorPort {
    private final Clock clock;

    public JwtTokenAdapter(Clock clock) {
        this.clock = clock;
    }

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;
    @Value("${application.security.jwt.expiration}")
    private long accessTokenExpiration;
    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshTokenExpiration;

    @Override
    public String generateAccessToken(User user) { return buildToken(user, accessTokenExpiration); }

    @Override
    public String generateRefreshToken(User user) { return buildToken(user, refreshTokenExpiration); }

    @Override
    public long getAccessTokenExpirationSeconds() { return accessTokenExpiration / 1000; }

    @Override
    public long getRefreshTokenExpirationSeconds() { return refreshTokenExpiration / 1000; }

    @Override
    public Long extractUserId(String token) {
        String subject = Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload()
            .getSubject();
        if (subject == null || !subject.startsWith("user-")) {
            throw new IllegalArgumentException("Invalid token subject");
        }
        return Long.parseLong(subject.substring("user-".length()));
    }

    @Override
    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public List<String> extractRoles(String token) {
        Object roles = parseClaims(token).get("roles");
        if (roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    @Override
    public List<String> extractScopes(String token) {
        Object scopes = parseClaims(token).get("scopes");
        if (scopes instanceof List<?> list) {
            return list.stream().map(String::valueOf).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private String buildToken(User user, long expiration) {
        Instant now = Instant.now(clock);
        return Jwts.builder()
            .setSubject("user-" + user.getId())
            .claim("roles", List.of(user.getRole().name()))
            .claim("scopes", user.getScopes())
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now.plusMillis(expiration)))
            .signWith(getSigningKey())
            .compact();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
    }

    private io.jsonwebtoken.Claims parseClaims(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
