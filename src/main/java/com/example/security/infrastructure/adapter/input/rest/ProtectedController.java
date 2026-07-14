package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.domain.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/protected")
public class ProtectedController {

    @GetMapping("/me")
    public Map<String, Object> me(Authentication authentication) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof User user) {
            return Map.of(
                    "userId", user.getId(),
                    "email", user.getEmail().getValue(),
                    "role", user.getRole().name()
            );
        }
        return Map.of(
                "principal", String.valueOf(principal)
        );
    }
}
