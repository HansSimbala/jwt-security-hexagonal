package com.example.security.domain.port.output;

import com.example.security.domain.model.Token;
import java.util.List;
import java.util.Optional;

public interface TokenRepositoryPort {
    Token save(Token token);
    List<Token> findAllValidTokensByUserId(Long userId);
    Optional<Token> findByValue(String tokenValue);
    void revokeAllUserTokens(Long userId);
}
