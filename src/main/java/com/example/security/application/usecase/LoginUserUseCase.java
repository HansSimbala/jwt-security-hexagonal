package com.example.security.application.usecase;

import com.example.security.application.dto.LoginCommand;
import com.example.security.application.dto.TokenResult;
import com.example.security.domain.exception.AccountLockedException;
import com.example.security.domain.exception.InvalidCredentialsException;
import com.example.security.domain.model.Email;
import com.example.security.domain.model.Password;
import com.example.security.domain.model.Token;
import com.example.security.domain.model.User;
import com.example.security.domain.port.input.LoginUserPort;
import com.example.security.domain.port.output.LoginAttemptPort;
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
    private final LoginAttemptPort loginAttemptPort;

    public LoginUserUseCase(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator,
            PasswordEncoderPort passwordEncoder,
            LoginAttemptPort loginAttemptPort) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.passwordEncoder = passwordEncoder;
        this.loginAttemptPort = loginAttemptPort;
    }

    @Override
    public TokenResult login(LoginCommand command) {
        Email email = Email.of(command.email());
        Password plainPassword = Password.ofPlainText(command.password());
        String emailValue = email.getValue();

        if (loginAttemptPort.isBlocked(emailValue)) {
            throw new AccountLockedException(emailValue, 15);
        }

        try {
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

            loginAttemptPort.loginSucceeded(emailValue);
            return TokenResult.of(accessToken, refreshToken, tokenGenerator.getAccessTokenExpirationSeconds());
        } catch (InvalidCredentialsException ex) {
            loginAttemptPort.loginFailed(emailValue);
            throw ex;
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
