package com.example.security.domain.port.output;

public interface RateLimitPort {
    boolean isAllowed(String key, int maxRequests, int windowMinutes);
    int getRemainingRequests(String key);
    long getResetTime(String key);
}
