package com.example.security.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitProperties {
    private boolean enabled = true;
    private EndpointLimit login = new EndpointLimit();
    private EndpointLimit register = new EndpointLimit();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public EndpointLimit getLogin() {
        return login;
    }

    public void setLogin(EndpointLimit login) {
        this.login = login;
    }

    public EndpointLimit getRegister() {
        return register;
    }

    public void setRegister(EndpointLimit register) {
        this.register = register;
    }

    public static class EndpointLimit {
        private int maxRequests;
        private int windowMinutes;

        public int getMaxRequests() {
            return maxRequests;
        }

        public void setMaxRequests(int maxRequests) {
            this.maxRequests = maxRequests;
        }

        public int getWindowMinutes() {
            return windowMinutes;
        }

        public void setWindowMinutes(int windowMinutes) {
            this.windowMinutes = windowMinutes;
        }
    }
}
