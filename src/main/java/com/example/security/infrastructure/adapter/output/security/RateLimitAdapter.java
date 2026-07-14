package com.example.security.infrastructure.adapter.output.security;

import com.example.security.domain.port.output.RateLimitPort;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class RateLimitAdapter implements RateLimitPort {
    private static final int CLEANUP_FREQUENCY = 100;

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final Clock clock;
    private final AtomicInteger operationCount = new AtomicInteger();

    public RateLimitAdapter(@Qualifier("rateLimitClock") Clock clock) {
        this.clock = clock;
    }

    @Override
    public boolean isAllowed(String key, int maxRequests, int windowMinutes) {
        validateLimits(maxRequests, windowMinutes);
        cleanupExpiredBucketsIfNeeded();

        Instant now = Instant.now(clock);
        AtomicBoolean allowed = new AtomicBoolean(true);
        Bucket bucket = buckets.compute(key, (k, existing) -> {
            if (existing == null || now.isAfter(existing.windowEnd())) {
                Instant windowEnd = now.plusSeconds((long) windowMinutes * 60L);
                return new Bucket(1, maxRequests, windowEnd);
            }

            if (existing.requests() >= existing.maxRequests()) {
                allowed.set(false);
                return existing;
            }

            return existing.withRequests(existing.requests() + 1);
        });
        return allowed.get() && bucket.requests() <= bucket.maxRequests();
    }

    @Override
    public int getRemainingRequests(String key) {
        Bucket bucket = currentBucket(key);
        if (bucket == null) {
            return 0;
        }
        return Math.max(bucket.maxRequests() - bucket.requests(), 0);
    }

    @Override
    public long getResetTime(String key) {
        Bucket bucket = currentBucket(key);
        if (bucket == null) {
            return Instant.now(clock).getEpochSecond();
        }
        return bucket.windowEnd().getEpochSecond();
    }

    private Bucket currentBucket(String key) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            return null;
        }
        if (Instant.now(clock).isAfter(bucket.windowEnd())) {
            buckets.remove(key);
            return null;
        }
        return bucket;
    }

    private void cleanupExpiredBucketsIfNeeded() {
        if (operationCount.incrementAndGet() % CLEANUP_FREQUENCY != 0) {
            return;
        }
        Instant now = Instant.now(clock);
        buckets.entrySet().removeIf(entry -> now.isAfter(entry.getValue().windowEnd()));
    }

    private void validateLimits(int maxRequests, int windowMinutes) {
        if (maxRequests <= 0) {
            throw new IllegalArgumentException("maxRequests must be greater than 0");
        }
        if (windowMinutes <= 0) {
            throw new IllegalArgumentException("windowMinutes must be greater than 0");
        }
    }

    private record Bucket(int requests, int maxRequests, Instant windowEnd) {
        private Bucket withRequests(int newRequests) {
            return new Bucket(newRequests, maxRequests, windowEnd);
        }
    }
}
