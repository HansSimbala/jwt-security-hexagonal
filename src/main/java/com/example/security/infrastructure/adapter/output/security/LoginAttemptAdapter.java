package com.example.security.infrastructure.adapter.output.security;

import com.example.security.domain.port.output.LoginAttemptPort;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginAttemptAdapter implements LoginAttemptPort {
    private static final int MAX_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;

    private final Map<String, Integer> attemptsCache = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockoutCache = new ConcurrentHashMap<>();
    private final Clock clock;

    public LoginAttemptAdapter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void loginFailed(String email) {
        if (isBlocked(email)) {
            return;
        }

        int attempts = attemptsCache.getOrDefault(email, 0) + 1;
        attemptsCache.put(email, attempts);

        if (attempts >= MAX_ATTEMPTS) {
            lockoutCache.put(email, Instant.now(clock).plus(Duration.ofMinutes(LOCKOUT_DURATION_MINUTES)));
        }
    }

    @Override
    public void loginSucceeded(String email) {
        resetAttempts(email);
    }

    @Override
    public boolean isBlocked(String email) {
        Instant lockedUntil = lockoutCache.get(email);
        if (lockedUntil == null) {
            return false;
        }

        if (Instant.now(clock).isAfter(lockedUntil)) {
            resetAttempts(email);
            return false;
        }

        return true;
    }

    @Override
    public int getAttempts(String email) {
        isBlocked(email);
        return attemptsCache.getOrDefault(email, 0);
    }

    @Override
    public void resetAttempts(String email) {
        attemptsCache.remove(email);
        lockoutCache.remove(email);
    }
}
