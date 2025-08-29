package com.payshield.frauddetector.application;

import com.payshield.frauddetector.domain.CaseRecord;
import com.payshield.frauddetector.domain.CaseState;
import com.payshield.frauddetector.domain.Invoice;
import com.payshield.frauddetector.domain.ports.CaseRepository;
import com.payshield.frauddetector.domain.ports.InvoiceRepository;
import com.payshield.frauddetector.infrastructure.adapters.OutboxPublisherAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class CaseApprovalService {

    private static final Logger log = LoggerFactory.getLogger(CaseApprovalService.class);

    private final CaseRepository cases;
    private final InvoiceRepository invoices;
    private final OutboxPublisherAdapter outboxPublisher;

    public CaseApprovalService(CaseRepository cases, InvoiceRepository invoices, OutboxPublisherAdapter outboxPublisher) {
        this.cases = cases;
        this.invoices = invoices;
        this.outboxPublisher = outboxPublisher;
    }

    @Transactional
    public void approve(UUID tenantId, UUID caseId) {
        log.info("Approving case - tenantId: {}, caseId: {}", tenantId, caseId);

        CaseRecord c = cases.findById(tenantId, caseId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Case not found"));

        // Idempotent: if already approved, nothing to do
        if (c.getState() == CaseState.APPROVED) {
            log.info("Case {} is already approved", caseId);
            return;
        }

        // Update case state
        cases.updateState(tenantId, caseId, CaseState.APPROVED);
        log.info("Case {} state updated to APPROVED", caseId);

        // Get the current user for audit trail
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String approvedBy = auth != null ? auth.getName() : "system";

        try {
            // Publish outbox event for case approval
            outboxPublisher.publishCaseApproved(tenantId, caseId, c.getInvoiceId(), approvedBy);
            log.info("Published case.approved event for case: {}", caseId);

        } catch (Exception e) {
            log.error("Failed to publish case.approved event for case {}: {}", caseId, e.getMessage(), e);
            // The transaction will still succeed, but the outbox event failed
            // This is acceptable as the core business logic (state change) succeeded
        }
    }

    @Transactional
    public void reject(UUID tenantId, UUID caseId) {
        log.info("Rejecting case - tenantId: {}, caseId: {}", tenantId, caseId);

        CaseRecord c = cases.findById(tenantId, caseId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Case not found"));

        // Idempotent: if already rejected, nothing to do
        if (c.getState() == CaseState.REJECTED) {
            log.info("Case {} is already rejected", caseId);
            return;
        }

        // Update case state
        cases.updateState(tenantId, caseId, CaseState.REJECTED);
        log.info("Case {} state updated to REJECTED", caseId);

        // Get the current user for audit trail
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String rejectedBy = auth != null ? auth.getName() : "system";

        try {
            // Publish outbox event for case rejection
            outboxPublisher.publishCaseRejected(tenantId, caseId, c.getInvoiceId(), rejectedBy, "Manual rejection");
            log.info("Published case.rejected event for case: {}", caseId);

        } catch (Exception e) {
            log.error("Failed to publish case.rejected event for case {}: {}", caseId, e.getMessage(), e);
            // The transaction will still succeed, but the outbox event failed
            // This is acceptable as the core business logic (state change) succeeded
        }
    }
}