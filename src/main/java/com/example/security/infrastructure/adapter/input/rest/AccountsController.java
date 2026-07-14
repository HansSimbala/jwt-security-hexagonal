package com.example.security.infrastructure.adapter.input.rest;

import com.example.security.infrastructure.adapter.input.annotation.RequireScope;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/accounts")
public class AccountsController {

    /**
     * Endpoint público para obtener información de cuentas.
     * Requiere scope: accounts:read
     *
     * Roles que pueden acceder:
     * - ADMIN: ✅ (tiene accounts:read)
     * - TELLER: ✅ (tiene accounts:read)
     * - CUSTOMER: ✅ (tiene accounts:read)
     */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_accounts:read')")
    @RequireScope("accounts:read")
    public ResponseEntity<Map<String, Object>> listAccounts() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("accounts", new Object[]{
            new Account(1L, "Cuenta Corriente", 5000.00),
            new Account(2L, "Cuenta Ahorros", 15000.00)
        });
        response.put("userId", auth.getPrincipal());
        response.put("requiredScope", "accounts:read");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint para crear/modificar cuentas.
     * Requiere scope: accounts:write
     *
     * Roles que pueden acceder:
     * - ADMIN: ✅ (tiene accounts:write)
     * - TELLER: ✅ (tiene accounts:write)
     * - CUSTOMER: ❌ (solo tiene accounts:read)
     */
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_accounts:write')")
    @RequireScope("accounts:write")
    public ResponseEntity<Map<String, Object>> createAccount(@RequestBody CreateAccountRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("id", 3L);
        response.put("name", request.getName());
        response.put("balance", request.getInitialBalance());
        response.put("userId", auth.getPrincipal());
        response.put("createdWith", "accounts:write scope (ADMIN/TELLER only)");
        response.put("requiredScope", "accounts:write");

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Endpoint para transferencias.
     * Requiere scope: transfers:create
     *
     * Roles que pueden acceder:
     * - ADMIN: ✅ (tiene transfers:create)
     * - TELLER: ✅ (tiene transfers:create)
     * - CUSTOMER: ❌ (no tiene transfers:create)
     */
    @PostMapping("/{id}/transfer")
    @PreAuthorize("hasAuthority('SCOPE_transfers:create')")
    @RequireScope("transfers:create")
    public ResponseEntity<Map<String, Object>> createTransfer(
            @PathVariable Long id,
            @RequestBody TransferRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("transferId", "TRF-" + System.currentTimeMillis());
        response.put("fromAccount", id);
        response.put("toAccount", request.getToAccountId());
        response.put("amount", request.getAmount());
        response.put("userId", auth.getPrincipal());
        response.put("requiredScope", "transfers:create");

        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint para gestionar beneficiarios.
     * Requiere scope: beneficiaries:manage
     *
     * Roles que pueden acceder:
     * - ADMIN: ✅ (tiene beneficiaries:manage)
     * - TELLER: ❌ (no tiene beneficiaries:manage)
     * - CUSTOMER: ❌ (no tiene beneficiaries:manage)
     */
    @PostMapping("/{id}/beneficiaries")
    @PreAuthorize("hasAuthority('SCOPE_beneficiaries:manage')")
    @RequireScope("beneficiaries:manage")
    public ResponseEntity<Map<String, Object>> addBeneficiary(
            @PathVariable Long id,
            @RequestBody AddBeneficiaryRequest request) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        Map<String, Object> response = new HashMap<>();
        response.put("beneficiaryId", "BEN-" + System.currentTimeMillis());
        response.put("accountId", id);
        response.put("beneficiaryName", request.getBeneficiaryName());
        response.put("beneficiaryEmail", request.getBeneficiaryEmail());
        response.put("userId", auth.getPrincipal());
        response.put("requiredScope", "beneficiaries:manage (ADMIN only)");

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ========== DTOs ==========

    public static class Account {
        private Long id;
        private String name;
        private Double balance;

        public Account(Long id, String name, Double balance) {
            this.id = id;
            this.name = name;
            this.balance = balance;
        }

        public Long getId() { return id; }
        public String getName() { return name; }
        public Double getBalance() { return balance; }
    }

    public static class CreateAccountRequest {
        private String name;
        private Double initialBalance;

        public String getName() { return name; }
        public Double getInitialBalance() { return initialBalance; }
    }

    public static class TransferRequest {
        private Long toAccountId;
        private Double amount;

        public Long getToAccountId() { return toAccountId; }
        public Double getAmount() { return amount; }
    }

    public static class AddBeneficiaryRequest {
        private String beneficiaryName;
        private String beneficiaryEmail;

        public String getBeneficiaryName() { return beneficiaryName; }
        public String getBeneficiaryEmail() { return beneficiaryEmail; }
    }
}
