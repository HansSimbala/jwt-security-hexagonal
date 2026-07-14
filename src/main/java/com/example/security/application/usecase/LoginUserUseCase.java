package com.example.security.application.usecase;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.InvalidCredentialsException;
import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Token;
import com.example.security.domain.model.User;
import com.example.security.domain.port.input.LoginUserPort;
import com.example.security.domain.port.output.PasswordEncoderPort;
import com.example.security.domain.port.output.TokenGeneratorPort;
import com.example.security.domain.port.output.TokenRepositoryPort;
import com.example.security.domain.port.output.UserRepositoryPort;
import java.time.Instant;

public class LoginUserUseCase implements LoginUserPort {

    private final UserRepositoryPort userRepository;
    private final TokenRepositoryPort tokenRepository;
    private final TokenGeneratorPort tokenGenerator;
    private final PasswordEncoderPort passwordEncoder;

    public LoginUserUseCase(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator,
            PasswordEncoderPort passwordEncoder) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public TokenResult login(LoginCommand command) {
        Email email = Email.of(command.email());
        Password plainPassword = Password.ofPlainText(command.password());

        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(plainPassword, user.getPassword())) {
            throw new InvalidCredentialsException();
        }

        tokenRepository.revokeAllUserTokens(user.getId());

        String accessToken = tokenGenerator.generateAccessToken(user);
        String refreshToken = tokenGenerator.generateRefreshToken(user);

        saveToken(user, accessToken, Token.TokenCategory.ACCESS);
        saveToken(user, refreshToken, Token.TokenCategory.REFRESH);

        return TokenResult.of(accessToken, refreshToken, tokenGenerator.getAccessTokenExpirationSeconds());
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
