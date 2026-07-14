package com.example.security.domain.exception;

public class RateLimitExceededException extends RuntimeException {
    private final int limit;
    private final int remaining;
    private final long resetEpochSeconds;

    public RateLimitExceededException(String message, int limit, int remaining, long resetEpochSeconds) {
        super(message);
        this.limit = limit;
        this.remaining = remaining;
        this.resetEpochSeconds = resetEpochSeconds;
    }

    public int getLimit() {
        return limit;
    }

    public int getRemaining() {
        return remaining;
    }

    public long getResetEpochSeconds() {
        return resetEpochSeconds;
    }
}
