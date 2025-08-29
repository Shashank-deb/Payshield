package com.payshield.frauddetector.api;

import com.payshield.frauddetector.config.TenantContext;
import com.payshield.frauddetector.infrastructure.adapters.OutboxPublisherAdapter;
import com.payshield.frauddetector.infrastructure.jpa.SpringOutboxRepository;
import com.payshield.frauddetector.infrastructure.outbox.OutboxDispatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

/**
 * Controller for testing and monitoring outbox functionality
 * Remove or secure this in production!
 */
@RestController
@RequestMapping("/outbox")
public class OutboxTestController {

    private static final Logger log = LoggerFactory.getLogger(OutboxTestController.class);
    
    private final OutboxPublisherAdapter publisher;
    private final OutboxDispatcher dispatcher;
    private final SpringOutboxRepository repository;

    public OutboxTestController(OutboxPublisherAdapter publisher, 
                               OutboxDispatcher dispatcher, 
                               SpringOutboxRepository repository) {
        this.publisher = publisher;
        this.dispatcher = dispatcher;
        this.repository = repository;
    }

    @PostMapping("/test/invoice-flagged")
    public ResponseEntity<?> testInvoiceFlagged() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            UUID invoiceId = UUID.randomUUID();
            UUID caseId = UUID.randomUUID();
            
            Map<String, Object> additionalData = Map.of(
                "vendorName", "Test Vendor Corp",
                "amount", "1500.00",
                "currency", "USD",
                "flaggedRules", "NEW_ACCOUNT,INVALID_FORMAT"
            );

            publisher.publishInvoiceFlagged(tenantId, invoiceId, caseId, additionalData);

            log.info("Test invoice.flagged event published - InvoiceId: {}, CaseId: {}", invoiceId, caseId);

            return ResponseEntity.ok(Map.of(
                "message", "Test invoice.flagged event published",
                "invoiceId", invoiceId.toString(),
                "caseId", caseId.toString(),
                "tenantId", tenantId.toString()
            ));
            
        } catch (Exception e) {
            log.error("Failed to publish test event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to publish test event", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/test/case-approved")
    public ResponseEntity<?> testCaseApproved() {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String approvedBy = auth != null ? auth.getName() : "test-user";
            
            UUID caseId = UUID.randomUUID();
            UUID invoiceId = UUID.randomUUID();

            publisher.publishCaseApproved(tenantId, caseId, invoiceId, approvedBy);

            log.info("Test case.approved event published - CaseId: {}, ApprovedBy: {}", caseId, approvedBy);

            return ResponseEntity.ok(Map.of(
                "message", "Test case.approved event published",
                "caseId", caseId.toString(),
                "invoiceId", invoiceId.toString(),
                "approvedBy", approvedBy
            ));
            
        } catch (Exception e) {
            log.error("Failed to publish test case.approved event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to publish test event", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/test/case-rejected")
    public ResponseEntity<?> testCaseRejected(@RequestBody(required = false) Map<String, String> body) {
        UUID tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
        }

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String rejectedBy = auth != null ? auth.getName() : "test-user";
            String reason = body != null ? body.get("reason") : "Suspicious activity detected";
            
            UUID caseId = UUID.randomUUID();
            UUID invoiceId = UUID.randomUUID();

            publisher.publishCaseRejected(tenantId, caseId, invoiceId, rejectedBy, reason);

            log.info("Test case.rejected event published - CaseId: {}, RejectedBy: {}", caseId, rejectedBy);

            return ResponseEntity.ok(Map.of(
                "message", "Test case.rejected event published",
                "caseId", caseId.toString(),
                "invoiceId", invoiceId.toString(),
                "rejectedBy", rejectedBy,
                "reason", reason
            ));
            
        } catch (Exception e) {
            log.error("Failed to publish test case.rejected event: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to publish test event", "message", e.getMessage())
            );
        }
    }

    @PostMapping("/process/{eventId}")
    public ResponseEntity<?> processEvent(@PathVariable UUID eventId) {
        try {
            dispatcher.processEventById(eventId);
            return ResponseEntity.ok(Map.of("message", "Event processed successfully", "eventId", eventId.toString()));
        } catch (Exception e) {
            log.error("Failed to process event {}: {}", eventId, e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to process event", "eventId", eventId.toString(), "message", e.getMessage())
            );
        }
    }

    @GetMapping("/stats")
    public ResponseEntity<?> getStats() {
        try {
            OutboxDispatcher.OutboxStats stats = dispatcher.getStats();
            
            return ResponseEntity.ok(Map.of(
                "pendingEvents", stats.pendingEvents(),
                "processedEvents", stats.processedEvents(),
                "dispatchEnabled", stats.dispatchEnabled(),
                "totalEvents", stats.pendingEvents() + stats.processedEvents()
            ));
        } catch (Exception e) {
            log.error("Failed to get outbox stats: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to get stats", "message", e.getMessage())
            );
        }
    }

    @GetMapping("/events")
    public ResponseEntity<?> getEvents(@RequestParam(defaultValue = "10") int limit) {
        try {
            UUID tenantId = TenantContext.getTenantId();
            if (tenantId == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Missing tenant context"));
            }

            var events = repository.findByTenantIdOrderByOccurredAtDesc(tenantId)
                    .stream()
                    .limit(limit)
                    .map(e -> Map.of(
                        "eventId", e.getEventId().toString(),
                        "type", e.getType(),
                        "occurredAt", e.getOccurredAt().toString(),
                        "processedAt", e.getProcessedAt() != null ? e.getProcessedAt().toString() : null,
                        "processed", e.isProcessed()
                    ))
                    .toList();

            return ResponseEntity.ok(Map.of("events", events, "tenantId", tenantId.toString()));
            
        } catch (Exception e) {
            log.error("Failed to get events: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(
                Map.of("error", "Failed to get events", "message", e.getMessage())
            );
        }
    }
}