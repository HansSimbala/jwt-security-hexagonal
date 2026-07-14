package com.example.security.infrastructure.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class MetricsService {
    private static final Logger log = LoggerFactory.getLogger(MetricsService.class);

    private final MeterRegistry meterRegistry;

    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter registrationSuccessCounter;
    private final Counter registrationFailureCounter;

    private final Counter jwtGeneratedCounter;
    private final Counter jwtValidatedCounter;
    private final Counter jwtExpiredCounter;
    private final Counter jwtInvalidCounter;
    private final Counter jwtRevokedCounter;
    private final Counter refreshTokenGeneratedCounter;
    private final Counter refreshTokenUsedCounter;

    private final Counter unauthorizedAccessCounter;
    private final Counter forbiddenAccessCounter;
    private final Counter invalidCredentialsCounter;
    private final Counter accountLockoutCounter;

    private final Timer loginTimer;
    private final Timer registrationTimer;
    private final Timer jwtValidationTimer;

    public MetricsService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;

        this.loginSuccessCounter = Counter.builder("auth.login.success")
                .description("Total de logins exitosos")
                .tag("type", "authentication")
                .register(meterRegistry);
        this.loginFailureCounter = Counter.builder("auth.login.failure")
                .description("Total de logins fallidos")
                .tag("type", "authentication")
                .register(meterRegistry);
        this.registrationSuccessCounter = Counter.builder("auth.registration.success")
                .description("Total de registros exitosos")
                .tag("type", "authentication")
                .register(meterRegistry);
        this.registrationFailureCounter = Counter.builder("auth.registration.failure")
                .description("Total de registros fallidos")
                .tag("type", "authentication")
                .register(meterRegistry);

        this.jwtGeneratedCounter = Counter.builder("jwt.token.generated")
                .description("Total de tokens JWT generados")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.jwtValidatedCounter = Counter.builder("jwt.token.validated")
                .description("Total de tokens JWT validados exitosamente")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.jwtExpiredCounter = Counter.builder("jwt.token.expired")
                .description("Total de tokens JWT expirados")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.jwtInvalidCounter = Counter.builder("jwt.token.invalid")
                .description("Total de tokens JWT invalidos")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.jwtRevokedCounter = Counter.builder("jwt.token.revoked")
                .description("Total de tokens JWT revocados")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.refreshTokenGeneratedCounter = Counter.builder("jwt.refresh_token.generated")
                .description("Total de refresh tokens generados")
                .tag("type", "jwt")
                .register(meterRegistry);
        this.refreshTokenUsedCounter = Counter.builder("jwt.refresh_token.used")
                .description("Total de refresh tokens utilizados")
                .tag("type", "jwt")
                .register(meterRegistry);

        this.unauthorizedAccessCounter = Counter.builder("security.access.unauthorized")
                .description("Total de intentos de acceso no autorizado (401)")
                .tag("type", "security")
                .register(meterRegistry);
        this.forbiddenAccessCounter = Counter.builder("security.access.forbidden")
                .description("Total de intentos de acceso prohibido (403)")
                .tag("type", "security")
                .register(meterRegistry);
        this.invalidCredentialsCounter = Counter.builder("security.credentials.invalid")
                .description("Total de credenciales invalidas")
                .tag("type", "security")
                .register(meterRegistry);
        this.accountLockoutCounter = Counter.builder("security.account.lockout")
                .description("Total de cuentas bloqueadas")
                .tag("type", "security")
                .register(meterRegistry);

        this.loginTimer = Timer.builder("auth.login.duration")
                .description("Duracion de operaciones de login")
                .tag("type", "authentication")
                .register(meterRegistry);
        this.registrationTimer = Timer.builder("auth.registration.duration")
                .description("Duracion de operaciones de registro")
                .tag("type", "authentication")
                .register(meterRegistry);
        this.jwtValidationTimer = Timer.builder("jwt.validation.duration")
                .description("Duracion de validacion de tokens JWT")
                .tag("type", "jwt")
                .register(meterRegistry);

        log.info("MetricsService initialized with custom business metrics");
    }

    public void incrementLoginSuccess() { loginSuccessCounter.increment(); }
    public void incrementLoginFailure() { loginFailureCounter.increment(); }
    public void incrementRegistrationSuccess() { registrationSuccessCounter.increment(); }
    public void incrementRegistrationFailure() { registrationFailureCounter.increment(); }
    public void incrementJwtGenerated() { jwtGeneratedCounter.increment(); }
    public void incrementJwtValidated() { jwtValidatedCounter.increment(); }
    public void incrementJwtExpired() { jwtExpiredCounter.increment(); }
    public void incrementJwtInvalid() { jwtInvalidCounter.increment(); }
    public void incrementJwtRevoked() { jwtRevokedCounter.increment(); }
    public void incrementRefreshTokenGenerated() { refreshTokenGeneratedCounter.increment(); }
    public void incrementRefreshTokenUsed() { refreshTokenUsedCounter.increment(); }
    public void incrementUnauthorizedAccess() { unauthorizedAccessCounter.increment(); }
    public void incrementForbiddenAccess() { forbiddenAccessCounter.increment(); }
    public void incrementInvalidCredentials() { invalidCredentialsCounter.increment(); }
    public void incrementAccountLockout() { accountLockoutCounter.increment(); }

    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    public <T> T recordLoginDuration(Timer.Sample sample, T result) {
        sample.stop(loginTimer);
        return result;
    }

    public <T> T recordRegistrationDuration(Timer.Sample sample, T result) {
        sample.stop(registrationTimer);
        return result;
    }

    public void recordJwtValidationDuration(long durationMs) {
        jwtValidationTimer.record(durationMs, TimeUnit.MILLISECONDS);
    }
}
