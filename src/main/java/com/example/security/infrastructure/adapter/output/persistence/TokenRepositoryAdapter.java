package com.example.security.infrastructure.adapter.output.persistence;

import com.example.security.domain.model.Token;
import com.example.security.domain.port.output.TokenRepositoryPort;
import com.example.security.infrastructure.adapter.output.persistence.entity.TokenJpaEntity;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Component
public class TokenRepositoryAdapter implements TokenRepositoryPort {
    private final TokenJpaRepository jpaRepository;

    public TokenRepositoryAdapter(TokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Token save(Token token) {
        TokenJpaEntity entity = new TokenJpaEntity();
        entity.setToken(token.getValue());
        entity.setTokenType(token.getType().name());
        entity.setTokenCategory(token.getCategory().name());
        entity.setUserId(token.getUserId());
        entity.setExpiresAt(token.getExpiresAt());
        entity.setRevoked(token.isRevoked());
        entity.setExpired(token.isExpired());
        TokenJpaEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    @Override
    public List<Token> findAllValidTokensByUserId(Long userId) {
        return jpaRepository.findAllValidTokensByUserId(userId).stream()
            .map(this::toDomain)
            .toList();
    }

    @Override
    public Optional<Token> findByValue(String tokenValue) {
        return jpaRepository.findByToken(tokenValue).map(this::toDomain);
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(Long userId) {
        jpaRepository.revokeAllByUserId(userId);
    }

    private Token toDomain(TokenJpaEntity entity) {
        return Token.builder()
            .id(entity.getId())
            .value(entity.getToken())
            .type(Token.TokenType.valueOf(entity.getTokenType()))
            .category(Token.TokenCategory.valueOf(entity.getTokenCategory()))
            .userId(entity.getUserId())
            .expiresAt(entity.getExpiresAt())
            .isRevoked(entity.isRevoked())
            .isExpired(entity.isExpired())
            .build();
    }
}
