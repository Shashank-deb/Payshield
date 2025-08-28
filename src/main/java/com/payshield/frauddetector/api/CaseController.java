package com.payshield.frauddetector.api;

import com.payshield.frauddetector.application.CaseApprovalService;
import com.payshield.frauddetector.config.TenantContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/cases")
public class CaseController {

    private static final Logger log = LoggerFactory.getLogger(CaseController.class);
    private final CaseApprovalService service;

    public CaseController(CaseApprovalService service) {
        this.service = service;
    }

    @PostMapping("/{id}/approve")
    public ResponseEntity<?> approve(@PathVariable("id") UUID id) {
        // Log authentication details
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UUID tenantId = TenantContext.getTenantId();

        log.info("Approve request - User: {}, Roles: {}, TenantId: {}, CaseId: {}",
                auth != null ? auth.getName() : "null",
                auth != null ? auth.getAuthorities() : "null",
                tenantId,
                id
        );

        if (tenantId == null) {
            log.error("No tenant ID found in context");
            return ResponseEntity.badRequest().body(
                    Map.of("error", "Missing tenant context", "message", "X-Tenant-Id header or JWT tenantId claim required")
            );
        }

        try {
            service.approve(tenantId, id);
            log.info("Case {} approved successfully by user {}", id, auth.getName());
            return ResponseEntity.ok(Map.of("status", "APPROVED"));
        } catch (Exception e) {
            log.error("Error approving case {}: {}", id, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                    Map.of("error", "Approval failed", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<?> reject(@PathVariable("id") UUID id) {
        // Log authentication details
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        UUID tenantId = TenantContext.getTenantId();

        log.info("Reject request - User: {}, Roles: {}, TenantId: {}, CaseId: {}",
                auth != null ? auth.getName() : "null",
                auth != null ? auth.getAuthorities() : "null",
                tenantId,
                id
        );

        if (tenantId == null) {
            log.error("No tenant ID found in context");
            return ResponseEntity.badRequest().body(
                    Map.of("error", "Missing tenant context", "message", "X-Tenant-Id header or JWT tenantId claim required")
            );
        }

        try {
            service.reject(tenantId, id);
            log.info("Case {} rejected successfully by user {}", id, auth.getName());
            return ResponseEntity.ok(Map.of("status", "REJECTED"));
        } catch (Exception e) {
            log.error("Error rejecting case {}: {}", id, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                    Map.of("error", "Rejection failed", "message", e.getMessage())
            );
        }
    }
}