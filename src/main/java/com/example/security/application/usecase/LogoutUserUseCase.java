package com.example.security.application.usecase;

import com.example.security.application.dto.LogoutCommand;
import com.example.security.domain.exception.InvalidTokenException;
import com.example.security.domain.model.Token;
import com.example.security.domain.port.input.LogoutUserPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import org.springframework.security.core.context.SecurityContextHolder;

public class LogoutUserUseCase implements LogoutUserPort {

    private final TokenRepositoryPort tokenRepository;

    public LogoutUserUseCase(TokenRepositoryPort tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    @Override
    public void logout(String tokenValue) {
        logout(new LogoutCommand(tokenValue));
    }

    public void logout(LogoutCommand command) {
        Token token = tokenRepository.findByValue(command.token())
                .orElseThrow(() -> new IllegalArgumentException("Token not found"));

        if (token.isRevoked() || token.isExpired()) {
            throw new InvalidTokenException("Token inválido o ausente");
        }

        token.revoke();
        token.markAsExpired();
        tokenRepository.revoke(token);
        SecurityContextHolder.clearContext();
    }

    @Override
    public void logoutAll(Long userId) {
        tokenRepository.revokeAllByUserId(userId);
        SecurityContextHolder.clearContext();
    }
}
