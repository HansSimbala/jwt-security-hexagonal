package com.example.security.infrastructure.adapter.output.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RateLimitAdapter Tests")
class RateLimitAdapterTest {

    @Test
    @DisplayName("Should allow requests within the limit")
    void shouldAllowRequestsWithinLimit() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        RateLimitAdapter adapter = new RateLimitAdapter(clock);
        String key = "login:127.0.0.1";

        assertThat(adapter.isAllowed(key, 3, 1)).isTrue();
        assertThat(adapter.isAllowed(key, 3, 1)).isTrue();
        assertThat(adapter.isAllowed(key, 3, 1)).isTrue();
        assertThat(adapter.getRemainingRequests(key)).isZero();
    }

    @Test
    @DisplayName("Should block when limit is exceeded")
    void shouldBlockWhenLimitIsExceeded() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        RateLimitAdapter adapter = new RateLimitAdapter(clock);
        String key = "login:127.0.0.1";

        assertThat(adapter.isAllowed(key, 2, 1)).isTrue();
        assertThat(adapter.isAllowed(key, 2, 1)).isTrue();
        assertThat(adapter.isAllowed(key, 2, 1)).isFalse();
        assertThat(adapter.getRemainingRequests(key)).isZero();
    }

    @Test
    @DisplayName("Should reset after window expires")
    void shouldResetAfterWindowExpires() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        RateLimitAdapter adapter = new RateLimitAdapter(clock);
        String key = "login:127.0.0.1";

        assertThat(adapter.isAllowed(key, 1, 1)).isTrue();
        assertThat(adapter.isAllowed(key, 1, 1)).isFalse();

        clock.advanceSeconds(61);

        assertThat(adapter.isAllowed(key, 1, 1)).isTrue();
        assertThat(adapter.getRemainingRequests(key)).isZero();
    }

    @Test
    @DisplayName("Should track different IPs independently")
    void shouldTrackDifferentIpsIndependently() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        RateLimitAdapter adapter = new RateLimitAdapter(clock);

        assertThat(adapter.isAllowed("login:10.0.0.1", 1, 1)).isTrue();
        assertThat(adapter.isAllowed("login:10.0.0.1", 1, 1)).isFalse();
        assertThat(adapter.isAllowed("login:10.0.0.2", 1, 1)).isTrue();
    }

    @Test
    @DisplayName("Should return remaining requests and reset time")
    void shouldReturnRemainingAndResetTime() {
        MutableClock clock = new MutableClock(Instant.parse("2026-03-23T00:00:00Z"));
        RateLimitAdapter adapter = new RateLimitAdapter(clock);
        String key = "register:127.0.0.1";

        adapter.isAllowed(key, 5, 60);
        adapter.isAllowed(key, 5, 60);

        assertThat(adapter.getRemainingRequests(key)).isEqualTo(3);
        assertThat(adapter.getResetTime(key)).isGreaterThan(clock.instant().getEpochSecond());
    }

    private static final class MutableClock extends Clock {
        private Instant instant;
        private final ZoneId zone;

        private MutableClock(Instant instant) {
            this.instant = instant;
            this.zone = ZoneId.of("UTC");
        }

        @Override
        public ZoneId getZone() {
            return zone;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return new MutableClock(instant);
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
