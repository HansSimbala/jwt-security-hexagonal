package com.example.security.domain.port.output;

import com.example.security.domain.model.User;
import java.util.List;

public interface TokenGeneratorPort {
    String generateAccessToken(User user);
    String generateRefreshToken(User user);
    long getAccessTokenExpirationSeconds();
    long getRefreshTokenExpirationSeconds();
    Long extractUserId(String token);
    boolean isTokenValid(String token);
    List<String> extractRoles(String token);
    List<String> extractScopes(String token);
}
