package com.example.security.infrastructure.config;

import com.example.security.application.usecase.LogoutUserUseCase;
import com.example.security.application.usecase.RefreshTokenUseCase;
import com.example.security.application.usecase.LoginUserUseCase;
import com.example.security.domain.port.input.LoginUserPort;
import com.example.security.domain.port.input.LogoutUserPort;
import com.example.security.domain.port.input.RefreshTokenPort;
import com.example.security.application.usecase.RegisterUserUseCase;
import com.example.security.domain.port.input.RegisterUserPort;
import com.example.security.domain.port.output.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.time.Clock;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class BeanConfig {
    @Bean
    public Clock clock() { return Clock.systemUTC(); }

    @Bean
    public PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean
    public LoginUserPort loginUserPort(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator,
            PasswordEncoderPort passwordEncoder,
            LoginAttemptPort loginAttemptPort) {
        return new LoginUserUseCase(
                userRepository,
                tokenRepository,
                tokenGenerator,
                passwordEncoder,
                loginAttemptPort);
    }

    @Bean
    public LogoutUserPort logoutUserPort(TokenRepositoryPort tokenRepository) {
        return new LogoutUserUseCase(tokenRepository);
    }

    @Bean
    public RefreshTokenPort refreshTokenPort(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator) {
        return new RefreshTokenUseCase(userRepository, tokenRepository, tokenGenerator);
    }

    @Bean
    public RegisterUserPort registerUserPort(
            UserRepositoryPort userRepository,
            TokenRepositoryPort tokenRepository,
            TokenGeneratorPort tokenGenerator,
            PasswordEncoderPort passwordEncoder) {
        return new RegisterUserUseCase(userRepository, tokenRepository, tokenGenerator, passwordEncoder);
    }
}
