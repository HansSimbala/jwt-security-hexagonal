package com.example.security.infrastructure.adapter.output.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("LoginAttemptAdapter Tests")
class LoginAttemptAdapterTest {

    @Test
    @DisplayName("Should not block with less than max attempts")
    void shouldNotBlockWithLessThanMaxAttempts() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);
        String email = "user1@test.com";

        for (int i = 0; i < 4; i++) {
            adapter.loginFailed(email);
        }

        assertThat(adapter.isBlocked(email)).isFalse();
        assertThat(adapter.getAttempts(email)).isEqualTo(4);
    }

    @Test
    @DisplayName("Should block after max failed attempts")
    void shouldBlockAfterMaxFailedAttempts() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);
        String email = "user2@test.com";

        for (int i = 0; i < 5; i++) {
            adapter.loginFailed(email);
        }

        assertThat(adapter.isBlocked(email)).isTrue();
        assertThat(adapter.getAttempts(email)).isEqualTo(5);
    }

    @Test
    @DisplayName("Should reset attempts after successful login")
    void shouldResetAttemptsAfterSuccessfulLogin() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);
        String email = "user3@test.com";

        adapter.loginFailed(email);
        adapter.loginFailed(email);
        adapter.loginSucceeded(email);

        assertThat(adapter.getAttempts(email)).isZero();
        assertThat(adapter.isBlocked(email)).isFalse();
    }

    @Test
    @DisplayName("Should reset attempts manually")
    void shouldResetAttemptsManually() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);
        String email = "user4@test.com";

        adapter.loginFailed(email);
        adapter.loginFailed(email);
        adapter.resetAttempts(email);

        assertThat(adapter.getAttempts(email)).isZero();
        assertThat(adapter.isBlocked(email)).isFalse();
    }

    @Test
    @DisplayName("Should track attempts independently per user")
    void shouldTrackAttemptsIndependentlyPerUser() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);

        for (int i = 0; i < 5; i++) {
            adapter.loginFailed("blocked@test.com");
        }
        adapter.loginFailed("open@test.com");

        assertThat(adapter.isBlocked("blocked@test.com")).isTrue();
        assertThat(adapter.isBlocked("open@test.com")).isFalse();
        assertThat(adapter.getAttempts("open@test.com")).isEqualTo(1);
    }

    @Test
    @DisplayName("Should unlock automatically after lockout duration")
    void shouldUnlockAutomaticallyAfterLockoutDuration() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);
        String email = "unlock@test.com";

        for (int i = 0; i < 5; i++) {
            adapter.loginFailed(email);
        }
        assertThat(adapter.isBlocked(email)).isTrue();

        clock.advanceSeconds(15 * 60 + 1);

        assertThat(adapter.isBlocked(email)).isFalse();
        assertThat(adapter.getAttempts(email)).isZero();
    }

    @ParameterizedTest
    @CsvFileSource(resources = "/testdata/brute-force-scenarios.csv", numLinesToSkip = 1)
    @DisplayName("Should match blocked status from CSV scenarios")
    void shouldMatchBlockedStatusFromCsvScenarios(String email, int attempts, boolean expectedBlocked) {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        LoginAttemptAdapter adapter = new LoginAttemptAdapter(clock);

        for (int i = 0; i < attempts; i++) {
            adapter.loginFailed(email);
        }

        assertThat(adapter.isBlocked(email)).isEqualTo(expectedBlocked);
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private final ZoneId zoneId;

        private MutableClock(Instant instant) {
            this(instant, ZoneId.of("UTC"));
        }

        private MutableClock(Instant instant, ZoneId zoneId) {
            this.instant = instant;
            this.zoneId = zoneId;
        }

        @Override
        public ZoneId getZone() {
            return zoneId;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant, zone);
        }

        @Override
        public Instant instant() {
            return instant;
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }
    }
}
