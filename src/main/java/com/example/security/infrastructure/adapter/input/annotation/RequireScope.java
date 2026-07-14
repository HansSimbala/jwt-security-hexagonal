package com.example.security.infrastructure.adapter.input.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotación para requerir un scope específico en un endpoint.
 * Se integra con @PreAuthorize para validación de OAuth scopes.
 *
 * Ejemplo:
 * @RequireScope("accounts:write")
 * @PostMapping("/accounts/{id}")
 * public ResponseEntity<Void> updateAccount(...) { }
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireScope {
    /**
     * @return el scope requerido (ej: "accounts:write", "transfers:create")
     */
    String value();
}
