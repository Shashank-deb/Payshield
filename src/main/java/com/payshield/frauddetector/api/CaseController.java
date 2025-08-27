package com.payshield.frauddetector.api;

import com.payshield.frauddetector.application.CaseApprovalService;
import com.payshield.frauddetector.config.TenantContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/cases")
public class CaseController {
    private final CaseApprovalService service;
    public CaseController(CaseApprovalService service){ this.service = service; }

    @PostMapping("/{id}/approve")
    public ResponseEntity<?> approve(@PathVariable("id") UUID id) {
        service.approve(TenantContext.getTenantId(), id);
        return ResponseEntity.ok(Map.of("status", "APPROVED"));
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<?> reject(@PathVariable("id") UUID id) {
        service.reject(TenantContext.getTenantId(), id);
        return ResponseEntity.ok(Map.of("status", "REJECTED"));
    }
}
