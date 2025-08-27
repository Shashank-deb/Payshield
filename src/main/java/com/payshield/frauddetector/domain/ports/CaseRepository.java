package com.payshield.frauddetector.domain.ports;

import com.payshield.frauddetector.domain.CaseRecord;
import com.payshield.frauddetector.domain.CaseState;

import java.util.Optional;
import java.util.UUID;

public interface CaseRepository {
    CaseRecord save(CaseRecord caseRecord);
    Optional<CaseRecord> findById(UUID tenantId, UUID caseId);
    void updateState(UUID tenantId, UUID caseId, CaseState newState);

}
