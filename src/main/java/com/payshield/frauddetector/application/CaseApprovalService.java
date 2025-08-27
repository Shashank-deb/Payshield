package com.payshield.frauddetector.application;

import com.payshield.frauddetector.domain.CaseRecord;
import com.payshield.frauddetector.domain.CaseState;
import com.payshield.frauddetector.domain.ports.CaseRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class CaseApprovalService {

    private final CaseRepository cases;

    public CaseApprovalService(CaseRepository cases) {
        this.cases = cases;
    }

    @Transactional
    public void approve(UUID tenantId, UUID caseId) {
        CaseRecord c = cases.findById(tenantId, caseId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Case not found"));

        // idempotent: if already approved, nothing to do
        if (c.getState() == CaseState.APPROVED) return;

        cases.updateState(tenantId, caseId, CaseState.APPROVED);
    }

    @Transactional
    public void reject(UUID tenantId, UUID caseId) {
        CaseRecord c = cases.findById(tenantId, caseId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Case not found"));

        if (c.getState() == CaseState.REJECTED) return;

        cases.updateState(tenantId, caseId, CaseState.REJECTED);
    }
}
