package com.example.security.application.usecase;

import com.example.security.application.dto.RefreshTokenCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.model.Token;
import com.example.security.domain.model.User;
import com.example.security.domain.port.input.RefreshTokenPort;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import com.example.security.domain.port.output.UserRepositoryPort;
import java.time.Instant;

public class RefreshTokenUseCase implements RefreshTokenPort {

    private final UserRepositoryPort userRepository;
    private final TokenRepositoryPort tokenRepository;
    private final TokenGeneratorPort tokenGenerator;

    public RefreshTokenUseCase(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public TokenResult refresh(String refreshToken) {
        return refresh(new RefreshTokenCommand(refreshToken));
    }

    public TokenResult refresh(RefreshTokenCommand command) {
        String tokenValue = command.refreshToken();
        Token storedRefreshToken = tokenRepository.findByValue(tokenValue)
                .orElseThrow(InvalidTokenException::new);

        if (!isStoredRefreshTokenUsable(storedRefreshToken)) {
            throw new InvalidTokenException();
        }

        if (!tokenGenerator.isTokenValid(tokenValue)) {
            throw new InvalidTokenException();
        }

        Long userId = tokenGenerator.extractUserId(tokenValue);
        if (!userId.equals(storedRefreshToken.getUserId())) {
            throw new InvalidTokenException();
        }

        User user = userRepository.findById(userId).orElseThrow(InvalidTokenException::new);

        tokenRepository.revokeAllUserTokens(user.getId());

        String newAccessToken = tokenGenerator.generateAccessToken(user);
        String newRefreshToken = tokenGenerator.generateRefreshToken(user);

        saveToken(user, newAccessToken, Token.TokenCategory.ACCESS);
        saveToken(user, newRefreshToken, Token.TokenCategory.REFRESH);

        return TokenResult.of(newAccessToken, newRefreshToken, tokenGenerator.getAccessTokenExpirationSeconds());
    }

    private boolean isStoredRefreshTokenUsable(Token token) {
        return token.getCategory() == Token.TokenCategory.REFRESH
                && !token.isRevoked()
                && !token.isExpired()
                && Instant.now().isBefore(token.getExpiresAt());
    }

    private void saveToken(User user, String tokenValue, Token.TokenCategory category) {
        long expirationSeconds = category == Token.TokenCategory.ACCESS
                ? tokenGenerator.getAccessTokenExpirationSeconds()
                : tokenGenerator.getRefreshTokenExpirationSeconds();

        Token token = Token.builder()
                .value(tokenValue)
                .category(category)
                .userId(user.getId())
                .expiresAt(Instant.now().plusSeconds(expirationSeconds))
                .build();

        tokenRepository.save(token);
    }
}
