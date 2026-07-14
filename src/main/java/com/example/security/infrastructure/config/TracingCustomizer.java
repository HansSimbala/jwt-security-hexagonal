package com.example.security.infrastructure.config;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;

public class TracingCustomizer {

    private final Tracer tracer;

    public TracingCustomizer(Tracer tracer) {
        this.tracer = tracer;
    }

    public void addTag(String key, String value) {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null) {
            currentSpan.tag(key, value);
        }
    }

    public void addEvent(String eventName) {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null) {
            currentSpan.event(eventName);
        }
    }

    public String getCurrentTraceId() {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null && currentSpan.context() != null) {
            return currentSpan.context().traceId();
        }
        return null;
    }

    public String getCurrentSpanId() {
        Span currentSpan = tracer.currentSpan();
        if (currentSpan != null && currentSpan.context() != null) {
            return currentSpan.context().spanId();
        }
        return null;
    }
}
