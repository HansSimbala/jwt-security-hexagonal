package com.example.security.application.usecase;

import com.example.security.application.dto.RegisterCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.InvalidRoleException;
import com.example.security.domain.exception.UserAlreadyExistsException;
import com.example.security.domain.model.*;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.domain.port.output.*;
import java.time.Instant;

public class RegisterUserUseCase implements RegisterUserPort {

    private final UserRepositoryPort userRepository;
    private final TokenRepositoryPort tokenRepository;
    private final TokenGeneratorPort tokenGenerator;
    private final PasswordEncoderPort passwordEncoder;

    public RegisterUserUseCase(
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
    public TokenResult register(RegisterCommand command) {
        Email email = Email.of(command.email());
        Password plainPassword = Password.ofPlainText(command.password());
        Role role = parseRole(command.role());

        if (userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException(email.getValue());
        }

        Password hashedPassword = passwordEncoder.encode(plainPassword);

        User user = User.builder()
                .name(command.name())
                .email(email)
                .password(hashedPassword)
                .role(role)
                .build();

        User savedUser = userRepository.save(user);

        String accessToken = tokenGenerator.generateAccessToken(savedUser);
        String refreshToken = tokenGenerator.generateRefreshToken(savedUser);

        saveToken(savedUser, accessToken, Token.TokenCategory.ACCESS);
        saveToken(savedUser, refreshToken, Token.TokenCategory.REFRESH);

        return TokenResult.of(accessToken, refreshToken, tokenGenerator.getAccessTokenExpirationSeconds());
    }

    private Role parseRole(String roleString) {
        try {
            return Role.fromString(roleString);
        } catch (IllegalArgumentException e) {
            throw new InvalidRoleException(roleString);
        }
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
